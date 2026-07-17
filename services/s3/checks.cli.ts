import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, writeFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import { ministackEnv as buildMinistackEnv } from '../_harness/aws-env';
import type { S3Contract } from './contract';

const execFileAsync = promisify(execFile);

/**
 * The AWS CLI behavioral oracle for the S3 vertical (epic #117, #139). Like
 * {@link checkSdk} it is defined ONCE and is provisioner-blind — but where the
 * SDK oracle proves the programmatic path, this one proves the EXACT commands a
 * human pastes into AWS CloudShell (or a terminal pointed at MiniStack):
 * `aws s3api put-object` then `aws s3api get-object`. That copy-pasteable
 * reproduction is the point of the CLI oracle (mirrors the Lambda vertical).
 *
 * `ministackEnv` is the environment the AWS CLI needs to talk to MiniStack:
 * `AWS_ENDPOINT_URL` + region + dummy `test`/`test` credentials, backfilled from
 * the shared `_harness/aws-env` module (each default applied only when the var
 * is absent, never overriding an explicit value) — so the documented commands
 * work whether you run them in CI (vars inherited) or reproduce them locally
 * against a MiniStack on the default port.
 *
 * Oracle (`checks.*.ts`): coverage-EXCLUDED, integration-tier only.
 */
export const ministackEnv: NodeJS.ProcessEnv = buildMinistackEnv(process.env);

export async function checkCli(c: S3Contract): Promise<void> {
  const body = 'hi from the s3 compat cli oracle';
  const key = `compat-s3-cli/${randomUUID()}.txt`;
  // Per-invocation temp files (unique names) that we read/write + unlink — the
  // idiomatic short-lived-scratch pattern (repo memory: no /tmp for DURABLE
  // scratch, but a per-call temp file that is read+unlinked is fine).
  const bodyFile = path.join(tmpdir(), `ministack-s3-put-${randomUUID()}.txt`);
  const outFile = path.join(tmpdir(), `ministack-s3-get-${randomUUID()}.txt`);

  // Args are passed to execFile as an argv ARRAY (never a shell string), so
  // there is no shell and no injection surface; the only interpolated values
  // are the bucket name from our own contract and our own generated key.
  try {
    await writeFile(bodyFile, body, 'utf8');

    await execFileAsync(
      'aws',
      [
        's3api',
        'put-object',
        '--bucket',
        c.bucketName,
        '--key',
        key,
        '--body',
        bodyFile,
      ],
      { env: ministackEnv },
    );

    await execFileAsync(
      'aws',
      ['s3api', 'get-object', '--bucket', c.bucketName, '--key', key, outFile],
      { env: ministackEnv },
    );

    const roundTripped = await readFile(outFile, 'utf8');
    expect(roundTripped).toBe(body);

    // Clean up the object so a reused emulator never accumulates test data.
    await execFileAsync(
      'aws',
      ['s3api', 'delete-object', '--bucket', c.bucketName, '--key', key],
      { env: ministackEnv },
    ).catch(() => undefined);
  } finally {
    await Promise.all([
      unlink(bodyFile).catch(() => undefined),
      unlink(outFile).catch(() => undefined),
    ]);
  }
}
