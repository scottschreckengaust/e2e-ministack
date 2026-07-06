import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as path from 'node:path';
import {
  LambdaClient,
  GetFunctionCommand,
  ResourceNotFoundException,
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
import { isFunctionConfigHealthy } from '../../health';
import { COMPAT_LAMBDA_FUNCTION_NAME } from './stack';

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

/**
 * Verify that `functionName` exists AND is healthy enough to skip provisioning.
 *
 * The healthy/absent classification is delegated to {@link isFunctionConfigHealthy}
 * (health.ts): a `GetFunction` that succeeds but returns an EXPLICIT bad state
 * (`State: Failed/Inactive` or `LastUpdateStatus: Failed`) is reported ABSENT so
 * the caller re-provisions (`cdk deploy` is idempotent). A genuinely missing
 * function (`ResourceNotFoundException`) is likewise absent.
 */
async function isFunctionPresent(functionName: string): Promise<boolean> {
  const lambda = new LambdaClient({
    endpoint: endpoint(process.env),
    region: region(process.env),
  });
  try {
    const res = await lambda.send(
      new GetFunctionCommand({ FunctionName: functionName }),
    );
    return isFunctionConfigHealthy(res.Configuration);
  } catch (err) {
    if (err instanceof ResourceNotFoundException) return false;
    throw err;
  }
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

export const cdkLambda: DeployAdapter<LambdaContract> = {
  name: 'cdk',
  async deploy(): Promise<LambdaContract> {
    if (!(await isFunctionPresent(COMPAT_LAMBDA_FUNCTION_NAME))) {
      await provisionCompatStack();
    }
    return { functionName: COMPAT_LAMBDA_FUNCTION_NAME };
  },
};
