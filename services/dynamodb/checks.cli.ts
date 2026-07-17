import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { randomUUID } from 'node:crypto';
import { ministackEnv as buildMinistackEnv } from '../_harness/aws-env';
import { COMPAT_DYNAMO_PARTITION_KEY } from './iac/cdk/construct';
import type { DynamoContract } from './contract';

const execFileAsync = promisify(execFile);

/**
 * The AWS CLI behavioral oracle for the DynamoDB vertical (epic #117, #140).
 * Like {@link checkSdk} it is defined ONCE and is provisioner-blind — but where
 * the SDK oracle proves the programmatic path, this one proves the EXACT
 * commands a human pastes into AWS CloudShell (or a terminal pointed at
 * MiniStack): `aws dynamodb put-item` then `aws dynamodb get-item`. That
 * copy-pasteable reproduction is the point of the CLI oracle (mirrors the
 * Lambda/S3 verticals).
 *
 * `ministackEnv` is the environment the AWS CLI needs to talk to MiniStack:
 * `AWS_ENDPOINT_URL` + region + dummy `test`/`test` credentials, backfilled from
 * the shared `_harness/aws-env` module (each default applied only when the var
 * is absent, never overriding an explicit value) — so the documented commands
 * work whether you run them in CI (vars inherited) or reproduce them locally
 * against a MiniStack on the default port.
 *
 * The item/key JSON is DynamoDB's attribute-value wire form
 * (`{"attr":{"S":"..."}}`) built with `JSON.stringify` and passed to `execFile`
 * as a single argv element — never a shell string, so there is no shell and no
 * injection surface; the only interpolated values are the table name from our
 * own contract and our own generated key.
 *
 * Oracle (`checks.*.ts`): coverage-EXCLUDED, integration-tier only.
 */
export const ministackEnv: NodeJS.ProcessEnv = buildMinistackEnv(process.env);

export async function checkCli(c: DynamoContract): Promise<void> {
  const pk = `compat-dynamo-cli/${randomUUID()}`;
  const payload = 'hi from the dynamodb compat cli oracle';
  const item = JSON.stringify({
    [COMPAT_DYNAMO_PARTITION_KEY]: { S: pk },
    payload: { S: payload },
  });
  const key = JSON.stringify({ [COMPAT_DYNAMO_PARTITION_KEY]: { S: pk } });

  try {
    await execFileAsync(
      'aws',
      ['dynamodb', 'put-item', '--table-name', c.tableName, '--item', item],
      { env: ministackEnv },
    );

    const { stdout } = await execFileAsync(
      'aws',
      [
        'dynamodb',
        'get-item',
        '--table-name',
        c.tableName,
        '--key',
        key,
        '--consistent-read',
      ],
      { env: ministackEnv },
    );

    const roundTripped = JSON.parse(stdout) as {
      Item?: { payload?: { S?: string } };
    };
    expect(roundTripped.Item?.payload?.S).toBe(payload);
  } finally {
    // Clean up the item so a reused emulator never accumulates test data.
    await execFileAsync(
      'aws',
      ['dynamodb', 'delete-item', '--table-name', c.tableName, '--key', key],
      { env: ministackEnv },
    ).catch(() => undefined);
  }
}
