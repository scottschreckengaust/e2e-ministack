import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as path from 'node:path';
import {
  S3Client,
  HeadBucketCommand,
  NotFound,
  NoSuchBucket,
} from '@aws-sdk/client-s3';
import type { DeployAdapter } from '../../../_harness/adapter';
import type { S3Contract } from '../../contract';
import {
  cdkBin,
  appCommand,
  bootstrapArgs,
  deployArgs,
  cdkExecOpts,
} from '../../../_harness/cdk';
import { endpoint, region } from '../../../_harness/aws-env';
import { isBucketHeadHealthy } from '../../health';
import { COMPAT_S3_BUCKET_NAME } from './stack';

const execFileAsync = promisify(execFile);

/**
 * The CDK {@link DeployAdapter} for the S3 vertical (epic #117, #139).
 *
 * VERIFY-OR-PROVISION against this vertical's OWN {@link CompatS3Stack}
 * (`compat-s3-bucket`) — it never touches the demo stack's `cdk-demo-bucket`.
 * This decouples the compat harness from `lib/ministack-stack.ts` so the vertical
 * works standalone (a fresh MiniStack with NO prior `cdk deploy`), not just in
 * the CI ordering that happens to deploy the demo stack first. `deploy()`:
 *
 *   1. VERIFY (fast path): `HeadBucket` for `compat-s3-bucket` at the MiniStack
 *      endpoint. If present, return the contract without redeploying (so
 *      idempotent re-runs never double-deploy).
 *   2. PROVISION (absent): on `NotFound`/`NoSuchBucket`, run `cdk bootstrap`
 *      (idempotent) then `cdk deploy CompatS3Stack` via the per-vertical app
 *      (iac/cdk/app.ts), then return the contract.
 *
 * `teardown` is intentionally omitted: cross-vertical reset uses
 * `POST /_ministack/reset` (the upstream pattern), and this adapter must NEVER
 * tear down the demo stack. A provisioned compat stack is left up so the verify
 * fast-path short-circuits subsequent runs.
 *
 * This file is a THIN I/O shell — all the pure, bug-prone logic (repoRoot / bin
 * resolution, the `--app` command + argv, the `AWS_ENDPOINT_URL_S3` backfill and
 * exec options, and the health classification) lives in the gated shared modules
 * (`services/_harness/cdk.ts`, `services/_harness/aws-env.ts`,
 * `services/s3/health.ts`), each held at the repo's 100% coverage gate. What
 * remains here is genuine I/O: the live SDK client and the two `cdk` execFile
 * calls. Mirrors the Lambda vertical's `deploy.ts`.
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
 * Verify that `bucketName` exists AND is healthy enough to skip provisioning.
 *
 * The healthy/absent classification is delegated to {@link isBucketHeadHealthy}
 * (health.ts): a `HeadBucket` that succeeds but reports an EXPLICIT non-2xx HTTP
 * status is treated as ABSENT so the caller re-provisions (`cdk deploy` is
 * idempotent). A genuinely missing bucket (`NotFound`/`NoSuchBucket`) is
 * likewise absent. `forcePathStyle` is required against the single-host emulator.
 */
async function isBucketPresent(bucketName: string): Promise<boolean> {
  const s3 = new S3Client({
    endpoint: endpoint(process.env),
    region: region(process.env),
    forcePathStyle: true,
  });
  try {
    const res = await s3.send(new HeadBucketCommand({ Bucket: bucketName }));
    return isBucketHeadHealthy(res);
  } catch (err) {
    if (err instanceof NotFound || err instanceof NoSuchBucket) return false;
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
    deployArgs('CompatS3Stack', compatAppCommand),
    opts,
  );
}

export const cdkS3: DeployAdapter<S3Contract> = {
  name: 'cdk',
  async deploy(): Promise<S3Contract> {
    if (!(await isBucketPresent(COMPAT_S3_BUCKET_NAME))) {
      await provisionCompatStack();
    }
    return { bucketName: COMPAT_S3_BUCKET_NAME };
  },
};
