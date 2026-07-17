import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CompatStack } from '../../../_harness/cdk-stack';
import { HardenedTable } from './construct';

/**
 * Physical name for the compat vertical's self-provisioned DynamoDB table.
 *
 * DELIBERATELY DISTINCT and `compat-*`-prefixed like the sibling verticals
 * (`compat-lambda-doubler`, `compat-s3-bucket`): MiniStack shares one global
 * namespace, so a distinct name keeps this stack independent of whether any
 * other stack is deployed — the #147 decoupling.
 */
export const COMPAT_DYNAMO_TABLE_NAME = 'compat-dynamo-table';

/**
 * The DynamoDB/CDK vertical's own self-provisioned compat stack (epic #117,
 * #140). It instantiates the reusable {@link HardenedTable} construct under a
 * distinct physical name so the compat harness can `cdk deploy` this stack
 * INDEPENDENTLY of the demo stack `lib/ministack-stack.ts`.
 *
 * This is the "compat = proof" half of the sample-vs-proof split: `lib/` stays a
 * decoupled demo (with its own `test/integration/integration.test.ts`), while
 * each compat vertical owns and provisions its own `Compat*Stack`. The CDK
 * adapter (iac/cdk/deploy.ts) verify-or-provisions THIS stack; the returned
 * {@link DynamoContract} names {@link COMPAT_DYNAMO_TABLE_NAME}. Mirrors the
 * Lambda vertical's {@link ../../../lambda/iac/cdk/stack.CompatLambdaStack} and
 * the S3 vertical's {@link ../../../s3/iac/cdk/stack.CompatS3Stack} — the third
 * vertical of the series.
 *
 * The deploy target's account/region are pinned to `MINISTACK_ENV` by the
 * {@link CompatStack} base — unconditionally, and `Omit<cdk.StackProps,'env'>`
 * makes passing `env` a compile error — the issue-#2 defense, keeping the deploy
 * target independent of the ambient `CDK_DEFAULT_*` the CDK CLI would otherwise
 * inject. The pin is written once in the base and inherited by every vertical.
 */
export class CompatDynamoStack extends CompatStack {
  constructor(
    scope: Construct,
    id: string,
    props?: Omit<cdk.StackProps, 'env'>,
  ) {
    super(scope, id, props);

    const table = new HardenedTable(this, 'Table', {
      tableName: COMPAT_DYNAMO_TABLE_NAME,
    });

    // Export the provisioned table name. This also gives the construct instance
    // a downstream consumer so static analysis sees it as used (Sonar S1848) —
    // instantiating a CDK construct registers it into the stack's scope as a
    // side effect the rule can't see.
    new cdk.CfnOutput(this, 'CompatTableName', {
      value: table.table.tableName,
    });
  }
}
