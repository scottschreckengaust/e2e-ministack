import * as path from 'node:path';
import { MINISTACK_ENV } from '../../lib/env';
import { MINISTACK_DEFAULT_ENDPOINT } from './aws-env';

/**
 * Shared CDK provisioning helpers for the compatibility harness (epic #117,
 * #147).
 *
 * The pure, bug-prone bits of a CDK {@link DeployAdapter} — the repoRoot path
 * arithmetic, the local bin resolution, the argument vectors, and the
 * `AWS_ENDPOINT_URL_S3` backfill — previously lived INSIDE the coverage-excluded
 * `iac/**\/deploy.ts`, which is why a repoRoot off-by-one once shipped green:
 * the logic was never unit-tested. Extracted here so every CDK vertical shares
 * ONE tested implementation held at the repo's 100% gate.
 */

// Repo root (…/e2e-ministack). This file is services/_harness/cdk.ts, so
// repoRoot is TWO levels up (_harness → services → repoRoot). `cdk` is invoked
// with cwd=repoRoot so it finds cdk.json + the repo-root `lambda/` asset
// regardless of where the test runner was launched from.
export const repoRoot = path.resolve(__dirname, '..', '..');

// Resolve the CDK CLI and ts-node from the repo's OWN node_modules/.bin — both
// are local devDependencies (there is no global `cdk`). Absolute paths are
// PATH-independent and pin to the locked aws-cdk / ts-node versions rather than
// whatever a PATH lookup finds. (Linux-only repo — MiniStack needs
// --network host — so the POSIX `.bin/<name>` path is correct.)
export const cdkBin = path.join(repoRoot, 'node_modules', '.bin', 'cdk');
export const tsNodeBin = path.join(repoRoot, 'node_modules', '.bin', 'ts-node');

/**
 * The `--app` command that runs a per-vertical CDK app entrypoint (a `.ts`
 * file) directly through the repo's pinned `ts-node --prefer-ts-exts` (mirrors
 * cdk.json's `app` for the demo stack). `entry` should be an absolute path so
 * cwd is irrelevant.
 */
export function appCommand(entry: string): string {
  return `${tsNodeBin} --prefer-ts-exts ${entry}`;
}

/**
 * `cdk bootstrap` argv for the given `--app` command. The target environment is
 * derived from {@link MINISTACK_ENV} — the single source of truth (S1) — so the
 * literal `aws://000000000000/us-east-1` is never hardcoded and can never drift
 * from `lib/env.ts`.
 */
export function bootstrapArgs(appCmd: string): string[] {
  return [
    'bootstrap',
    `aws://${MINISTACK_ENV.account}/${MINISTACK_ENV.region}`,
    '--app',
    appCmd,
  ];
}

/** `cdk deploy <stackName>` argv for the given `--app` command. */
export function deployArgs(stackName: string, appCmd: string): string[] {
  return ['deploy', stackName, '--require-approval', 'never', '--app', appCmd];
}

// execFile's default `maxBuffer` is 1 MiB of combined stdout/stderr; when a
// child exceeds it Node KILLS the process (ERR_CHILD_PROCESS_STDIO_MAXBUFFER)
// and rejects — mid-deploy. A cold `cdk bootstrap`/`cdk deploy` with verbose
// cdk-nag output, asset-bundling logs, and streamed CloudFormation events can
// cross 1 MiB, aborting the deploy. 64 MiB is ample headroom for cdk's
// chattiest output without meaningfully bounding memory.
export const CDK_MAX_BUFFER = 64 * 1024 * 1024;

/**
 * A copy of `env` with `AWS_ENDPOINT_URL_S3` backfilled for the `cdk` child
 * processes.
 *
 * This is a PRESENCE requirement, not an addressing one (S6 — the earlier
 * comment wrongly claimed "S3 virtual-host addressing can't be inferred from the
 * generic endpoint"). The bare CDK CLI throws
 * "If specifying 'AWS_ENDPOINT_URL' then 'AWS_ENDPOINT_URL_S3' must be
 * specified" whenever the generic endpoint is set but the S3-specific one is
 * not. The CI Integration "Run integration tests" step sets `AWS_ENDPOINT_URL`
 * but deliberately OMITS `AWS_ENDPOINT_URL_S3` (only the dedicated
 * bootstrap/deploy steps set it). Since `cdk bootstrap`/`cdk deploy` run INSIDE
 * that test step here, we backfill the S3 var to the SAME endpoint — which
 * satisfies the presence check (MiniStack serves S3 on the same port). Falls
 * through to the MiniStack default when neither var is set.
 */
export function cdkEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return {
    ...env,
    AWS_ENDPOINT_URL_S3:
      env.AWS_ENDPOINT_URL_S3 ??
      env.AWS_ENDPOINT_URL ??
      MINISTACK_DEFAULT_ENDPOINT,
  };
}

/**
 * The shared `execFile` options for both the `cdk bootstrap` and `cdk deploy`
 * calls: cwd pinned to {@link repoRoot}, the S3-backfilled {@link cdkEnv}, and
 * the enlarged {@link CDK_MAX_BUFFER}.
 */
export function cdkExecOpts(env: NodeJS.ProcessEnv) {
  return { cwd: repoRoot, env: cdkEnv(env), maxBuffer: CDK_MAX_BUFFER };
}
