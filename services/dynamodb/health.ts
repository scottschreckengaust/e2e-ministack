import { TableStatus, type TableDescription } from '@aws-sdk/client-dynamodb';

/**
 * DynamoDB-vertical health predicate for the compatibility harness (epic #117,
 * #140). This is PER-VERTICAL — the Lambda vertical classifies a `GetFunction`
 * response and the S3 vertical a `HeadBucket` response; this one interprets a
 * `DescribeTable` response.
 *
 * `DescribeTable` succeeding proves the table OBJECT exists, not that it is
 * usable: a prior run killed mid-create (or a table stuck `DELETING`/`ARCHIVING`)
 * can leave a half-usable table. Only an EXPLICIT bad status counts as
 * unhealthy: `ARCHIVED`, `ARCHIVING`, `DELETING`,
 * `INACCESSIBLE_ENCRYPTION_CREDENTIALS`, or `REPLICATION_NOT_AUTHORIZED`. A
 * caller that sees `false` re-provisions (`cdk deploy` is idempotent, so
 * re-running is cheap and safe).
 *
 * `ACTIVE` (what MiniStack returns for a healthy table), the transient
 * `CREATING`/`UPDATING` states, AND an absent/unknown status are ALL treated as
 * healthy — so an emulator that omits the field never defeats the verify
 * fast-path by making the table look broken. (A genuinely missing table
 * surfaces as a thrown `ResourceNotFoundException` at the call site, not as a
 * response this predicate ever sees.)
 */
export function isTableHealthy(desc: TableDescription | undefined): boolean {
  const status = desc?.TableStatus;
  const broken =
    status === TableStatus.ARCHIVED ||
    status === TableStatus.ARCHIVING ||
    status === TableStatus.DELETING ||
    status === TableStatus.INACCESSIBLE_ENCRYPTION_CREDENTIALS ||
    status === TableStatus.REPLICATION_NOT_AUTHORIZED;
  return !broken;
}

/**
 * PROVENANCE predicate for the verify-or-provision adapter (mirrors #175's
 * Lambda pattern for DynamoDB).
 *
 * A `DescribeTable` that succeeds proves only that SOME table of that name
 * exists — not that THIS stack provisioned it. A stale leftover, or a foreign
 * table that happens to share `compat-dynamo-table`, would otherwise let the
 * integration oracle green without ever exercising a freshly-provisioned
 * {@link HardenedTable}. So the adapter reads the table's key schema back and
 * requires the EXACT distinctive partition-key attribute name only that
 * construct sets (`COMPAT_DYNAMO_PARTITION_KEY`); this predicate is that pure
 * check.
 *
 * The partition key is the chosen PRIMARY marker because `DescribeTable`
 * returns `KeySchema` + `AttributeDefinitions` reliably in the
 * `TableDescription` (a first-class part of the table description MiniStack
 * always echoes), whereas tags are a side table (`ListTagsOfResource`) the
 * emulator may or may not surface. Deliberately EXACT-match and
 * marker-passed-in: the expected value lives in the construct (the single
 * source of truth for what gets provisioned) and is threaded through here, so
 * `health.ts` stays free of any CDK import. An absent/empty/foreign HASH key is
 * `false` (fail loudly / re-provision); only the exact marker is `true`.
 */
export function hasProvenanceMarker(
  desc: TableDescription | undefined,
  expectedPartitionKey: string,
): boolean {
  const hashKey = desc?.KeySchema?.find((k) => k.KeyType === 'HASH');
  return hashKey?.AttributeName === expectedPartitionKey;
}
