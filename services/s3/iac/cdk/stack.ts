import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CompatStack } from '../../../_harness/cdk-stack';
import { HardenedBucket } from './construct';

/**
 * Physical name for the compat vertical's self-provisioned data bucket.
 *
 * DELIBERATELY DISTINCT from the demo stack's `cdk-demo-bucket`
 * (lib/ministack-stack.ts): MiniStack shares one global namespace, so a compat
 * stack that reused `cdk-demo-bucket` would collide with the demo stack whenever
 * both are deployed (as in CI, where `cdk deploy` of the demo stack precedes the
 * integration tier). A distinct name makes the harness independent of whether
 * the demo stack is deployed at all — this is the #147 decoupling.
 */
export const COMPAT_S3_BUCKET_NAME = 'compat-s3-bucket';

/**
 * The S3/CDK vertical's own self-provisioned compat stack (epic #117, #139). It
 * instantiates the reusable {@link HardenedBucket} construct under a distinct
 * physical name so the compat harness can `cdk deploy` this stack INDEPENDENTLY
 * of the demo stack `lib/ministack-stack.ts`.
 *
 * This is the "compat = proof" half of the sample-vs-proof split: `lib/` stays a
 * decoupled demo (with its own `test/integration/integration.test.ts`), while
 * each compat vertical owns and provisions its own `Compat*Stack`. The CDK
 * adapter (iac/cdk/deploy.ts) verify-or-provisions THIS stack; the returned
 * {@link S3Contract} names {@link COMPAT_S3_BUCKET_NAME}. Mirrors the Lambda
 * vertical's {@link ../../../lambda/iac/cdk/stack.CompatLambdaStack} — the
 * second vertical of the series (DynamoDB follows in #140).
 *
 * The deploy target's account/region are pinned to `MINISTACK_ENV` by the
 * {@link CompatStack} base — unconditionally, and `Omit<cdk.StackProps,'env'>`
 * makes passing `env` a compile error — the issue-#2 defense, keeping the deploy
 * target independent of the ambient `CDK_DEFAULT_*` the CDK CLI would otherwise
 * inject. The pin is written once in the base and inherited by every vertical.
 */
export class CompatS3Stack extends CompatStack {
  constructor(
    scope: Construct,
    id: string,
    props?: Omit<cdk.StackProps, 'env'>,
  ) {
    super(scope, id, props);

    const data = new HardenedBucket(this, 'Bucket', {
      bucketName: COMPAT_S3_BUCKET_NAME,
    });

    // Export the provisioned bucket name. This also gives the construct instance
    // a downstream consumer so static analysis sees it as used (Sonar S1848) —
    // instantiating a CDK construct registers it into the stack's scope as a
    // side effect the rule can't see.
    new cdk.CfnOutput(this, 'DataBucketName', {
      value: data.bucket.bucketName,
    });
  }
}
