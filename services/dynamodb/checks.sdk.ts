import { randomUUID } from 'node:crypto';
import {
  DynamoDBClient,
  PutItemCommand,
  GetItemCommand,
  DeleteItemCommand,
} from '@aws-sdk/client-dynamodb';
import { endpoint, region } from '../_harness/aws-env';
import { COMPAT_DYNAMO_PARTITION_KEY } from './iac/cdk/construct';
import type { DynamoContract } from './contract';

/**
 * The typed AWS SDK v3 behavioral oracle for the DynamoDB vertical (epic #117,
 * #140). Defined ONCE and reused by every IaC tool — it takes only a
 * {@link DynamoContract} and never knows which tool provisioned the table, which
 * is what keeps it provisioner-blind (mirrors the Lambda/S3 verticals'
 * `checkSdk`).
 *
 * It does a full item ROUND-TRIP: `PutItem` an item under a unique partition-key
 * value carrying a payload attribute, `GetItem` it back with a
 * `ConsistentRead`, and assert the payload round-trips. The item is deleted
 * afterward so repeated runs against a long-lived/reused emulator stay
 * idempotent (issue #10) — the delete runs in a `finally` so a failed assertion
 * still cleans up.
 *
 * The partition-key attribute name is the construct's
 * {@link COMPAT_DYNAMO_PARTITION_KEY} (the single source of truth for the table
 * schema), so the oracle can never drift from the deployed key.
 *
 * This is an oracle (`checks.*.ts`): coverage-EXCLUDED (jest.config.js) and run
 * only in the integration tier against a live MiniStack. The endpoint and region
 * come from the shared `_harness/aws-env` module; the dummy test/test
 * credentials are accepted by MiniStack.
 */
export async function checkSdk(c: DynamoContract): Promise<void> {
  const ddb = new DynamoDBClient({
    endpoint: endpoint(process.env),
    region: region(process.env),
  });

  const TableName = c.tableName;
  const pk = `compat-dynamo/${randomUUID()}`;
  const payload = 'hi from the dynamodb compat oracle';
  const Key = { [COMPAT_DYNAMO_PARTITION_KEY]: { S: pk } };

  try {
    await ddb.send(
      new PutItemCommand({
        TableName,
        Item: {
          [COMPAT_DYNAMO_PARTITION_KEY]: { S: pk },
          payload: { S: payload },
        },
      }),
    );
    const got = await ddb.send(
      new GetItemCommand({ TableName, Key, ConsistentRead: true }),
    );
    expect(got.Item?.payload?.S).toBe(payload);
  } finally {
    // Best-effort cleanup so a reused emulator never accumulates test items;
    // ignore if the PUT never landed.
    await ddb
      .send(new DeleteItemCommand({ TableName, Key }))
      .catch(() => undefined);
  }
}
