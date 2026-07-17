import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import * as path from 'node:path';
import {
  DynamoDBClient,
  DescribeTableCommand,
  ResourceNotFoundException,
  type TableDescription,
} from '@aws-sdk/client-dynamodb';
import type { DeployAdapter } from '../../../_harness/adapter';
import type { DynamoContract } from '../../contract';
import {
  cdkBin,
  appCommand,
  bootstrapArgs,
  deployArgs,
  cdkExecOpts,
} from '../../../_harness/cdk';
import { endpoint, region } from '../../../_harness/aws-env';
import { isTableHealthy, hasProvenanceMarker } from '../../health';
import { COMPAT_DYNAMO_TABLE_NAME } from './stack';
import { COMPAT_DYNAMO_PARTITION_KEY } from './construct';

const execFileAsync = promisify(execFile);

/**
 * The CDK {@link DeployAdapter} for the DynamoDB vertical (epic #117, #140).
 *
 * VERIFY-OR-PROVISION against this vertical's OWN {@link CompatDynamoStack}
 * (`compat-dynamo-table`) — it never touches the demo stack. This decouples the
 * compat harness from `lib/ministack-stack.ts` so the vertical works standalone
 * (a fresh MiniStack with NO prior `cdk deploy`), not just in the CI ordering
 * that happens to deploy the demo stack first. `deploy()`:
 *
 *   1. VERIFY (fast path): `DescribeTable` for `compat-dynamo-table` at the
 *      MiniStack endpoint. If present, healthy, AND carrying this stack's
 *      provenance marker, return the contract without redeploying (so idempotent
 *      re-runs never double-deploy).
 *   2. PROVISION (absent): on `ResourceNotFoundException`, run `cdk bootstrap`
 *      (idempotent) then `cdk deploy CompatDynamoStack` via the per-vertical app
 *      (iac/cdk/app.ts), then return the contract.
 *   3. PROVE PROVENANCE (mirrors #175): on BOTH paths, `DescribeTable` once more
 *      and assert the table's HASH key is the {@link COMPAT_DYNAMO_PARTITION_KEY}
 *      marker that ONLY {@link HardenedTable}/{@link CompatDynamoStack} sets. If
 *      it is absent the table is stale or foreign (someone else created a
 *      `compat-dynamo-table`) — throw loudly rather than let the oracle green
 *      against a resource THIS stack never provisioned. This closes the
 *      verify-short-circuit gap and neutralizes the S1848 intent: the
 *      construct's synth output is now tied to a runtime assertion.
 *
 * The fast-path optimization is preserved — a matching marker still skips the
 * `cdk deploy` — but it is now GATED on the marker, so it can only short-circuit
 * against a table this stack actually owns.
 *
 * `teardown` is intentionally omitted: cross-vertical reset uses
 * `POST /_ministack/reset` (the upstream pattern), and this adapter must NEVER
 * tear down what it did not provision. A provisioned compat stack is left up so
 * the verify fast-path short-circuits subsequent runs.
 *
 * This file is a THIN I/O shell — all the pure, bug-prone logic (repoRoot / bin
 * resolution, the `--app` command + argv, the `AWS_ENDPOINT_URL_S3` backfill and
 * exec options, and the health/provenance classification) lives in the gated
 * shared modules (`services/_harness/cdk.ts`, `services/_harness/aws-env.ts`,
 * `services/dynamodb/health.ts`), each held at the repo's 100% coverage gate.
 * What remains here is genuine I/O: the live SDK client and the two `cdk`
 * execFile calls. Mirrors the Lambda/S3 verticals' `deploy.ts`.
 *
 * Integration-tier only (coverage-excluded via the `iac/**\/deploy.ts` path
 * convention in jest.config.js) — it needs a live MiniStack and cannot run in
 * the unit tier.
 */

// The per-vertical CDK app entrypoint (Decision #2: the vertical owns its own
// app — this is NOT bin/app.ts). Absolute path so cwd is irrelevant; the argv
// builders and bin resolution come from the shared harness.
const compatAppCommand = appCommand(path.join(__dirname, 'app.ts'));

const dynamoClient = (): DynamoDBClient =>
  new DynamoDBClient({
    endpoint: endpoint(process.env),
    region: region(process.env),
  });

/**
 * `DescribeTable`'s `Table` description, or `undefined` if the table is
 * genuinely missing (`ResourceNotFoundException`). Any other error propagates.
 */
async function getTableDescription(
  tableName: string,
): Promise<TableDescription | undefined> {
  try {
    const res = await dynamoClient().send(
      new DescribeTableCommand({ TableName: tableName }),
    );
    return res.Table;
  } catch (err) {
    if (err instanceof ResourceNotFoundException) return undefined;
    throw err;
  }
}

/**
 * Verify that `tableName` exists, is healthy enough to skip provisioning, AND
 * carries this stack's provenance marker (mirrors #175).
 *
 * The classification is delegated to the gated pure predicates in health.ts:
 * {@link isTableHealthy} (a `DescribeTable` that succeeds but reports an EXPLICIT
 * bad status is reported ABSENT so the caller re-provisions — `cdk deploy` is
 * idempotent) AND {@link hasProvenanceMarker} (a table WITHOUT the distinctive
 * partition key this stack sets is treated as NOT ours, so the fast-path won't
 * short-circuit against it — the caller re-provisions instead). A genuinely
 * missing table is likewise absent.
 */
async function isTablePresent(tableName: string): Promise<boolean> {
  const desc = await getTableDescription(tableName);
  return (
    isTableHealthy(desc) &&
    hasProvenanceMarker(desc, COMPAT_DYNAMO_PARTITION_KEY)
  );
}

async function provisionCompatStack(): Promise<void> {
  // `cdk bootstrap` is idempotent — safe on every provision; the target/env come
  // from the harness (MINISTACK_ENV + the AWS_ENDPOINT_URL_S3 backfill).
  const opts = cdkExecOpts(process.env);
  await execFileAsync(cdkBin, bootstrapArgs(compatAppCommand), opts);
  await execFileAsync(
    cdkBin,
    deployArgs('CompatDynamoStack', compatAppCommand),
    opts,
  );
}

/**
 * Read the table back and PROVE it is the one THIS stack provisioned (mirrors
 * #175).
 *
 * Runs after both `deploy()` paths (fast-path skip AND fresh provision). If the
 * live table's HASH key is not the {@link COMPAT_DYNAMO_PARTITION_KEY} marker
 * only {@link HardenedTable} sets, it is stale/foreign — throw loudly so the
 * integration tier fails visibly instead of greening against a table this stack
 * never provisioned.
 */
async function assertProvenance(tableName: string): Promise<void> {
  const desc = await getTableDescription(tableName);
  if (!hasProvenanceMarker(desc, COMPAT_DYNAMO_PARTITION_KEY)) {
    const hashKey = desc?.KeySchema?.find((k) => k.KeyType === 'HASH');
    throw new Error(
      `Provenance check failed: table "${tableName}" is missing the ` +
        `CompatDynamoStack/HardenedTable marker partition key ` +
        `"${COMPAT_DYNAMO_PARTITION_KEY}" ` +
        `(got HASH key: ${JSON.stringify(hashKey?.AttributeName)}). A stale or ` +
        `foreign table of the same name was found — refusing to run the oracle ` +
        `against a resource this stack did not provision.`,
    );
  }
}

export const cdkDynamo: DeployAdapter<DynamoContract> = {
  name: 'cdk',
  async deploy(): Promise<DynamoContract> {
    if (!(await isTablePresent(COMPAT_DYNAMO_TABLE_NAME))) {
      await provisionCompatStack();
    }
    // Prove provenance on BOTH paths: the fast-path only skipped because the
    // marker already matched, and a fresh provision must land the marker. A
    // stale/foreign table of the same name fails loudly here.
    await assertProvenance(COMPAT_DYNAMO_TABLE_NAME);
    return { tableName: COMPAT_DYNAMO_TABLE_NAME };
  },
};
