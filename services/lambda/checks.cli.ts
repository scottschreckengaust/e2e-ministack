import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFile, unlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import * as path from 'node:path';
import type { LambdaContract } from './contract';

const execFileAsync = promisify(execFile);

/**
 * The AWS CLI behavioral oracle for the Lambda vertical (epic #117,
 * sub-issue B / #136). Like {@link checkSdk} it is defined ONCE and is
 * provisioner-blind — but where the SDK oracle proves the programmatic path,
 * this one proves the EXACT command a human pastes into AWS CloudShell (or a
 * terminal pointed at MiniStack). That copy-pasteable reproduction is the
 * point of the CLI oracle.
 *
 * `ministackEnv` is the environment the AWS CLI needs to talk to MiniStack:
 * `AWS_ENDPOINT_URL` + region + dummy `test`/`test` credentials. In CI these
 * are all set at the integration-job level and inherited, so the helper is just
 * `{ ...process.env }` with the same defaults the SDK oracle uses applied only
 * when a var is absent — so the documented command works whether you run it in
 * CI (vars inherited) or reproduce it locally against a MiniStack on the
 * default port. It never overrides an explicitly-set value.
 *
 * Oracle (`checks.*.ts`): coverage-EXCLUDED, integration-tier only.
 */
export const ministackEnv: NodeJS.ProcessEnv = {
  ...process.env,
  AWS_ENDPOINT_URL: process.env.AWS_ENDPOINT_URL ?? 'http://localhost:4566',
  AWS_REGION: process.env.AWS_REGION ?? 'us-east-1',
  AWS_DEFAULT_REGION: process.env.AWS_DEFAULT_REGION ?? 'us-east-1',
  AWS_ACCESS_KEY_ID: process.env.AWS_ACCESS_KEY_ID ?? 'test',
  AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY ?? 'test',
};

/**
 * Invoke the function once via the AWS CLI and return its parsed response
 * payload. The response body is written to a per-invocation temp file
 * (`os.tmpdir()`, unique name) which we read + parse + unlink — writing invoke
 * output to `/dev/stdout` is finicky under execFile, and a short-lived temp
 * file we immediately reap is the idiomatic pattern (repo memory: no /tmp for
 * DURABLE scratch, but a per-call temp file that is read+unlinked is fine).
 *
 * Args are passed to execFile as an argv ARRAY (never a shell string), so there
 * is no shell and no injection surface; the only interpolated value is the
 * function name from our own contract, and the payload is base64 with
 * `--cli-binary-format raw-in-base64-out`.
 */
async function invokeViaCli(
  functionName: string,
  payload: unknown,
): Promise<{ statusCode: number; doubled?: number; nodeVersion?: string }> {
  const outFile = path.join(
    tmpdir(),
    `ministack-lambda-invoke-${randomUUID()}.json`,
  );
  try {
    await execFileAsync(
      'aws',
      [
        'lambda',
        'invoke',
        '--function-name',
        functionName,
        '--payload',
        Buffer.from(JSON.stringify(payload)).toString('base64'),
        '--cli-binary-format',
        'raw-in-base64-out',
        outFile,
      ],
      { env: ministackEnv },
    );
    const body = await readFile(outFile, 'utf8');
    return JSON.parse(body);
  } finally {
    // Best-effort cleanup; ignore if the CLI never created the file.
    await unlink(outFile).catch(() => undefined);
  }
}

export async function checkCli(c: LambdaContract): Promise<void> {
  // Happy path: 21 → 42, on the Node 24 runtime.
  const ok = await invokeViaCli(c.functionName, { n: 21 });
  expect(ok.statusCode).toBe(200);
  expect(ok.doubled).toBe(42);
  expect(ok.nodeVersion).toMatch(/^v24\./);

  // Handled 400: non-numeric input returns a 400 envelope (does not throw).
  const bad = await invokeViaCli(c.functionName, { n: 'abc' });
  expect(bad.statusCode).toBe(400);
}
