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
 * Integration-tier only (coverage-excluded via the `iac/**\/deploy.ts` path
 * convention in jest.config.js) — it needs a live MiniStack and cannot run in
 * the unit tier.
 */

const endpoint = process.env.AWS_ENDPOINT_URL ?? 'http://localhost:4566';
const region = process.env.AWS_DEFAULT_REGION ?? 'us-east-1';

// Repo root (…/e2e-ministack) — this file is services/lambda/iac/cdk/deploy.ts,
// four levels down (cdk → iac → lambda → services → repoRoot). cdk is invoked
// with cwd=repoRoot so cdk.json + the repo-root `lambda/` asset resolve
// regardless of where jest is launched from.
const repoRoot = path.resolve(__dirname, '..', '..', '..', '..');

// Resolve the CDK CLI and ts-node from the repo's OWN node_modules/.bin
// (both are local devDependencies — there is no global `cdk`). Absolute
// paths remove all PATH dependence, so the adapter provisions correctly
// whether launched via `npm run` (which injects node_modules/.bin) or a
// bare test runner, and pins to the locked aws-cdk / ts-node versions
// rather than whatever a PATH lookup finds. (Linux-only repo — MiniStack
// needs --network host — so the POSIX `.bin/<name>` path is correct.)
const cdkBin = path.join(repoRoot, 'node_modules', '.bin', 'cdk');
const tsNodeBin = path.join(repoRoot, 'node_modules', '.bin', 'ts-node');

// The per-vertical CDK app entrypoint (Decision #2: the vertical owns its own
// app — this is NOT bin/app.ts). Passed to `--app`; the .ts path is resolved
// absolutely so cwd is irrelevant. The local pinned `ts-node --prefer-ts-exts`
// runs the .ts directly (mirrors cdk.json's `app` for the demo stack).
const compatAppEntry = path.join(__dirname, 'app.ts');
const compatAppCommand = `${tsNodeBin} --prefer-ts-exts ${compatAppEntry}`;

/**
 * Environment for the `cdk` execFile calls.
 *
 * CRITICAL (#147): the CI Integration job's "Run integration tests" step sets
 * only `AWS_ENDPOINT_URL` + region + creds and deliberately OMITS
 * `AWS_ENDPOINT_URL_S3` (per .github/workflows/ci.yml / AGENTS.md — only the
 * dedicated bootstrap/deploy steps set it). But `cdk bootstrap`/`cdk deploy` run
 * INSIDE that test step here and BOTH need `AWS_ENDPOINT_URL_S3` for
 * asset/staging-bucket upload (S3 virtual-host addressing can't be inferred from
 * the generic endpoint — omitting it makes cdk throw). So we backfill it,
 * defaulting to the generic endpoint. Account/region come from `MINISTACK_ENV`
 * in the compat app, so `CDK_DEFAULT_*` is not required.
 */
const cdkEnv: NodeJS.ProcessEnv = {
  ...process.env,
  AWS_ENDPOINT_URL_S3:
    process.env.AWS_ENDPOINT_URL_S3 ??
    process.env.AWS_ENDPOINT_URL ??
    'http://localhost:4566',
};

async function isFunctionPresent(functionName: string): Promise<boolean> {
  const lambda = new LambdaClient({ endpoint, region });
  try {
    await lambda.send(new GetFunctionCommand({ FunctionName: functionName }));
    return true;
  } catch (err) {
    if (err instanceof ResourceNotFoundException) return false;
    throw err;
  }
}

async function provisionCompatStack(): Promise<void> {
  // `cdk bootstrap` is idempotent — safe to run on every provision. The env is
  // pinned by MINISTACK_ENV in the compat app, matching the repo bootstrap
  // target aws://000000000000/us-east-1.
  await execFileAsync(
    cdkBin,
    ['bootstrap', 'aws://000000000000/us-east-1', '--app', compatAppCommand],
    { cwd: repoRoot, env: cdkEnv },
  );

  await execFileAsync(
    cdkBin,
    [
      'deploy',
      'CompatLambdaStack',
      '--require-approval',
      'never',
      '--app',
      compatAppCommand,
    ],
    { cwd: repoRoot, env: cdkEnv },
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
