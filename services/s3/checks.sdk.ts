import { randomUUID } from 'node:crypto';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { endpoint, region } from '../_harness/aws-env';
import type { S3Contract } from './contract';

/**
 * The typed AWS SDK v3 behavioral oracle for the S3 vertical (epic #117, #139).
 * Defined ONCE and reused by every IaC tool — it takes only an {@link S3Contract}
 * and never knows which tool provisioned the bucket, which is what keeps it
 * provisioner-blind (mirrors the Lambda vertical's `checkSdk`).
 *
 * Assertions reach parity with the S3 round-trip in the existing
 * `test/integration/integration.test.ts`: PUT an object under a unique key, GET
 * it back, and assert the body round-trips byte-for-byte. The written object is
 * deleted afterward so repeated runs against a long-lived/reused emulator stay
 * idempotent (issue #10) — the delete runs in a `finally` so a failed assertion
 * still cleans up.
 *
 * `forcePathStyle: true` is required for S3 against a single-host emulator
 * (MiniStack serves every service on one endpoint, so virtual-host bucket
 * addressing can't resolve) — same as the demo integration test.
 *
 * This is an oracle (`checks.*.ts`): coverage-EXCLUDED (jest.config.js) and run
 * only in the integration tier against a live MiniStack. The endpoint and region
 * come from the shared `_harness/aws-env` module; the dummy test/test
 * credentials are accepted by MiniStack.
 */
export async function checkSdk(c: S3Contract): Promise<void> {
  const s3 = new S3Client({
    endpoint: endpoint(process.env),
    region: region(process.env),
    forcePathStyle: true,
  });

  const Bucket = c.bucketName;
  const Key = `compat-s3/${randomUUID()}.txt`;
  const Body = 'hi from the s3 compat oracle';

  try {
    await s3.send(new PutObjectCommand({ Bucket, Key, Body }));
    const got = await s3.send(new GetObjectCommand({ Bucket, Key }));
    const roundTripped = await got.Body!.transformToString();
    expect(roundTripped).toBe(Body);
  } finally {
    // Best-effort cleanup so a reused emulator never accumulates test objects;
    // ignore if the PUT never landed.
    await s3
      .send(new DeleteObjectCommand({ Bucket, Key }))
      .catch(() => undefined);
  }
}
