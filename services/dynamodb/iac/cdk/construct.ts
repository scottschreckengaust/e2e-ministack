import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as kms from 'aws-cdk-lib/aws-kms';

/**
 * The distinctive partition-key attribute name this construct stamps on the
 * table — the PRIMARY provenance marker (mirrors #175's Lambda pattern).
 *
 * The integration adapter (iac/cdk/deploy.ts) reads it back via `DescribeTable`
 * after deploy — on the verify fast-path AND after a fresh provision — and fails
 * loudly if the table's HASH key is not this exact name, so a stale or foreign
 * table of the same physical name can never let the integration tier green
 * without exercising a freshly-provisioned `HardenedTable`. The partition key is
 * chosen as the primary marker because `DescribeTable` returns `KeySchema` +
 * `AttributeDefinitions` reliably in the `TableDescription` (a first-class part
 * of the table description MiniStack always echoes), whereas tags are a side
 * table (`ListTagsOfResource`) the emulator may or may not surface. See
 * deploy.ts for the read-back.
 */
export const COMPAT_DYNAMO_PARTITION_KEY = 'e2e_ministack_compat_pk';

/**
 * Secondary provenance marker: a CDK tag on the table. Belt-and-braces
 * alongside {@link COMPAT_DYNAMO_PARTITION_KEY} — it makes the ownership claim
 * visible to anyone listing tags and is asserted in the synthesized template,
 * but the partition key is the marker the deploy read-back keys on because it is
 * the more reliably returned field on MiniStack.
 */
export const COMPAT_DYNAMO_PROVENANCE_TAG = {
  key: 'e2e-ministack:compat',
  value: 'dynamo-table',
} as const;

/** Props for {@link HardenedTable}. */
export interface HardenedTableProps {
  /**
   * Physical name of the table. Defaults to `cdk-demo-table` (a demo-style name
   * for standalone/verbatim reuse), but the compat stack
   * ({@link CompatDynamoStack} in iac/cdk/stack.ts) OVERRIDES it to
   * `compat-dynamo-table` on purpose: MiniStack shares one global namespace, so
   * leaving the default could collide with any demo table of the same name
   * whenever both are deployed. Pass a distinct `compat-*` name in any stack
   * that provisions this construct alongside other stacks.
   */
  readonly tableName?: string;
}

/**
 * Standalone, reusable hardened DynamoDB table — the construct fragment the
 * MiniStack compat harness exposes for the DynamoDB/CDK vertical (epic #117,
 * #140).
 *
 * Unlike the Lambda/S3 verticals (which mirror a construct that already exists
 * inline in `lib/ministack-stack.ts`), this authors a FRESH hardened resource:
 * a `dynamodb.Table` with
 *   - **Point-in-time recovery enabled** (cdk-nag AwsSolutions-DDB3),
 *   - **customer-managed KMS encryption** on a rotated CMK (defense-in-depth
 *     beyond the AWS-owned default; checkov CKV_AWS_119),
 *   - **PAY_PER_REQUEST billing** (no provisioned-capacity autoscaling to nag),
 *   - a `DESTROY` removal policy (MiniStack is ephemeral; no
 *     autoDeleteObjects-style custom resource that stalls the emulator).
 * so it passes the cdk-nag AwsSolutions pack cleanly.
 *
 * The table's partition key is {@link COMPAT_DYNAMO_PARTITION_KEY} — a
 * distinctive name that doubles as the vertical's PRIMARY provenance marker,
 * read back by the CDK {@link DeployAdapter} (iac/cdk/deploy.ts) to prove THIS
 * stack provisioned the table. A secondary CDK tag
 * ({@link COMPAT_DYNAMO_PROVENANCE_TAG}) is applied belt-and-braces.
 *
 * This construct is the reusable building block the vertical PROVISIONS: it is
 * instantiated by {@link CompatDynamoStack} (iac/cdk/stack.ts), which the CDK
 * {@link DeployAdapter} (iac/cdk/deploy.ts) verify-or-provisions against a live
 * MiniStack (#147). It is deliberately NOT added to the demo stack
 * `lib/ministack-stack.ts` — that stays the decoupled "sample", while each
 * compat vertical owns and deploys its own `Compat*Stack` (the sample-vs-proof
 * split). It is exercised in full by the pure-synth unit test
 * `test/unit/services/dynamodb-construct.test.ts`, which holds it under the
 * repo's 100% coverage gate.
 *
 * WARNING — do NOT deploy unchanged to a real AWS account: the fixed table name
 * below is deliberate here only because MiniStack isolates its namespace.
 */
export class HardenedTable extends Construct {
  /** The underlying table, exposed so callers can grant/wire it. */
  public readonly table: dynamodb.Table;

  constructor(scope: Construct, id: string, props: HardenedTableProps = {}) {
    super(scope, id);

    const tableName = props.tableName ?? 'cdk-demo-table';

    // Dedicated rotated CMK for table encryption (defense-in-depth beyond the
    // AWS-owned default key; checkov CKV_AWS_119). DESTROY so a MiniStack reset
    // never leaves an orphaned key.
    const tableKey = new kms.Key(this, 'TableKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.table = new dynamodb.Table(this, 'Table', {
      tableName,
      // Distinctive partition key that doubles as the primary provenance marker
      // (deploy.ts reads it back via DescribeTable). A stale/foreign table of
      // the same name lacks it, so the adapter fails loudly.
      partitionKey: {
        name: COMPAT_DYNAMO_PARTITION_KEY,
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      // AwsSolutions-DDB3: continuous backups / point-in-time recovery.
      pointInTimeRecoverySpecification: {
        pointInTimeRecoveryEnabled: true,
      },
      // Customer-managed KMS encryption on the rotated CMK above.
      encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
      encryptionKey: tableKey,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Secondary provenance marker: a CDK tag scoped to the table.
    cdk.Tags.of(this.table).add(
      COMPAT_DYNAMO_PROVENANCE_TAG.key,
      COMPAT_DYNAMO_PROVENANCE_TAG.value,
    );
  }
}
