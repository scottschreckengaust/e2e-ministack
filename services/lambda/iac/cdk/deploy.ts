import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as path from 'node:path';
import {
  LambdaClient,
  GetFunctionCommand,
  ResourceNotFoundException,
  type FunctionConfiguration,
} from '@aws-sdk/client-lambda';
import type { DeployAdapter } from '../../../_harness/adapter';
import type { LambdaContract } from '../../contract';
import {
  cdkBin,
  appCommand,
  bootstrapArgs,
  deployArgs,
  cdkExecOpts,
} from '../../../_harness/cdk';
import { endpoint, region } from '../../../_harness/aws-env';
import { isFunctionConfigHealthy, hasProvenanceMarker } from '../../health';
import { COMPAT_LAMBDA_FUNCTION_NAME } from './stack';
import { DOUBLER_PROVENANCE_DESCRIPTION } from './construct';

const execFileAsync = promisify(execFile);

/**
 * The CDK {@link DeployAdapter} for the Lambda vertical (epic #117, #147).
 *
 * VERIFY-OR-PROVISION against this vertical's OWN {@link CompatLambdaStack}
 * (`compat-lambda-doubler`) — it no longer short-circuits to the demo stack's
 * `cdk-doubler`. This decouples the compat harness from `lib/ministack-stack.ts`
 * so the vertical works standalone (a fresh MiniStack with NO prior
 * `cdk deploy`), not just in the CI ordering that happens to deploy the demo
 * stack first. `deploy()`:
 *
 *   1. VERIFY (fast path): `GetFunction` for `compat-lambda-doubler` at the
 *      MiniStack endpoint. If present, return the contract without redeploying
 *      (so idempotent re-runs never double-deploy).
 *   2. PROVISION (absent): on `ResourceNotFoundException`, run `cdk bootstrap`
 *      (idempotent) then `cdk deploy CompatLambdaStack` via the per-vertical app
 *      (iac/cdk/app.ts), then return the contract.
 *   3. PROVE PROVENANCE (#175): on BOTH paths, `GetFunction` once more and
 *      assert the function carries the {@link DOUBLER_PROVENANCE_DESCRIPTION}
 *      marker that ONLY {@link DoublerFunction}/{@link CompatLambdaStack} stamps.
 *      If it is absent the function is stale or foreign (someone else created a
 *      `compat-lambda-doubler`) — throw loudly rather than let the oracle green
 *      against a resource THIS stack never provisioned. This closes the
 *      verify-short-circuit gap and neutralizes the S1848 intent: the
 *      construct's synth output is now tied to a runtime assertion.
 *
 * The fast-path optimization is preserved — a matching marker still skips the
 * ~16s `cdk deploy` — but it is now GATED on the marker, so it can only
 * short-circuit against a function this stack actually owns.
 *
 * `teardown` is intentionally omitted: cross-vertical reset uses
 * `POST /_ministack/reset` (the upstream pattern), and this adapter must NEVER
 * tear down the demo stack. A provisioned compat stack is left up so the verify
 * fast-path short-circuits subsequent runs.
 *
 * This file is a THIN I/O shell — all the pure, bug-prone logic (repoRoot / bin
 * resolution, the `--app` command + argv, the `AWS_ENDPOINT_URL_S3` backfill and
 * exec options, and the health classification) lives in the gated shared
 * modules (`services/_harness/cdk.ts`, `services/_harness/aws-env.ts`,
 * `services/lambda/health.ts`), each held at the repo's 100% coverage gate. What
 * remains here is genuine I/O: the live SDK client and the two `cdk` execFile
 * calls.
 *
 * Integration-tier only (coverage-excluded via the `iac/**\/deploy.ts` path
 * convention in jest.config.js) — it needs a live MiniStack and cannot run in
 * the unit tier.
 */

// The per-vertical CDK app entrypoint (Decision #2: the vertical owns its own
// app — this is NOT bin/app.ts). Absolute path so cwd is irrelevant; the argv
// builders and bin resolution come from the shared harness.
const compatAppCommand = appCommand(path.join(__dirname, 'app.ts'));

const lambdaClient = (): LambdaClient =>
  new LambdaClient({
    endpoint: endpoint(process.env),
    region: region(process.env),
  });

/**
 * `GetFunction`'s `Configuration`, or `undefined` if the function is genuinely
 * missing (`ResourceNotFoundException`). Any other error propagates.
 */
async function getFunctionConfig(
  functionName: string,
): Promise<FunctionConfiguration | undefined> {
  try {
    const res = await lambdaClient().send(
      new GetFunctionCommand({ FunctionName: functionName }),
    );
    return res.Configuration;
  } catch (err) {
    if (err instanceof ResourceNotFoundException) return undefined;
    throw err;
  }
}

/**
 * Verify that `functionName` exists, is healthy enough to skip provisioning,
 * AND carries this stack's provenance marker (#175).
 *
 * The classification is delegated to the gated pure predicates in health.ts:
 * {@link isFunctionConfigHealthy} (a `GetFunction` that succeeds but returns an
 * EXPLICIT bad state is reported ABSENT so the caller re-provisions —
 * `cdk deploy` is idempotent) AND {@link hasProvenanceMarker} (a function
 * WITHOUT the marker this stack stamps is treated as NOT ours, so the fast-path
 * won't short-circuit against it — the caller re-provisions instead). A
 * genuinely missing function is likewise absent.
 */
async function isFunctionPresent(functionName: string): Promise<boolean> {
  const cfg = await getFunctionConfig(functionName);
  return (
    isFunctionConfigHealthy(cfg) &&
    hasProvenanceMarker(cfg, DOUBLER_PROVENANCE_DESCRIPTION)
  );
}

async function provisionCompatStack(): Promise<void> {
  // `cdk bootstrap` is idempotent — safe on every provision; the target/env come
  // from the harness (MINISTACK_ENV + the AWS_ENDPOINT_URL_S3 backfill).
  const opts = cdkExecOpts(process.env);
  await execFileAsync(cdkBin, bootstrapArgs(compatAppCommand), opts);
  await execFileAsync(
    cdkBin,
    deployArgs('CompatLambdaStack', compatAppCommand),
    opts,
  );
}

/**
 * Read the function back and PROVE it is the one THIS stack provisioned (#175).
 *
 * Runs after both `deploy()` paths (fast-path skip AND fresh provision). If the
 * live function lacks the {@link DOUBLER_PROVENANCE_DESCRIPTION} marker only
 * {@link DoublerFunction} stamps, it is stale/foreign — throw loudly so the
 * integration tier fails visibly instead of greening against a function this
 * stack never provisioned.
 */
async function assertProvenance(functionName: string): Promise<void> {
  const cfg = await getFunctionConfig(functionName);
  if (!hasProvenanceMarker(cfg, DOUBLER_PROVENANCE_DESCRIPTION)) {
    throw new Error(
      `Provenance check failed (#175): function "${functionName}" is missing the ` +
        `CompatLambdaStack/DoublerFunction marker Description ` +
        `"${DOUBLER_PROVENANCE_DESCRIPTION}" ` +
        `(got: ${JSON.stringify(cfg?.Description)}). A stale or foreign function ` +
        `of the same name was found — refusing to run the oracle against a ` +
        `resource this stack did not provision.`,
    );
  }
}

export const cdkLambda: DeployAdapter<LambdaContract> = {
  name: 'cdk',
  async deploy(): Promise<LambdaContract> {
    if (!(await isFunctionPresent(COMPAT_LAMBDA_FUNCTION_NAME))) {
      await provisionCompatStack();
    }
    // Prove provenance on BOTH paths: the fast-path only skipped because the
    // marker already matched, and a fresh provision must land the marker. A
    // stale/foreign function of the same name fails loudly here.
    await assertProvenance(COMPAT_LAMBDA_FUNCTION_NAME);
    return { functionName: COMPAT_LAMBDA_FUNCTION_NAME };
  },
};
