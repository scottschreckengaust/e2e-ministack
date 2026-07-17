import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as path from 'node:path';

/**
 * Provenance marker set on the function's Lambda `Description` (#175).
 *
 * This is the PRIMARY, distinctive marker that ONLY this construct stamps. The
 * integration adapter (iac/cdk/deploy.ts) reads it back via `GetFunction` after
 * deploy — on the verify fast-path AND after a fresh provision — and fails
 * loudly if it is absent, so a stale or foreign function of the same name can
 * never let the integration tier green without exercising a freshly-provisioned
 * `DoublerFunction`. Description is chosen as the primary marker because
 * `GetFunction` returns it reliably in `Configuration.Description` (a
 * first-class field of the function configuration MiniStack always echoes),
 * whereas tags are a side table the emulator may or may not surface on
 * `GetFunction`. See deploy.ts for the read-back.
 */
export const DOUBLER_PROVENANCE_DESCRIPTION =
  'e2e-ministack compat DoublerFunction (CompatLambdaStack) — provisioned marker #175';

/**
 * Secondary provenance marker: a CDK tag on the function (#175). Belt-and-braces
 * alongside {@link DOUBLER_PROVENANCE_DESCRIPTION} — it makes the ownership
 * claim visible to anyone listing tags and is asserted in the synthesized
 * template, but the Description is the marker the deploy read-back keys on
 * because it is the more reliably returned field on MiniStack.
 */
export const DOUBLER_PROVENANCE_TAG = {
  key: 'e2e-ministack:compat',
  value: 'lambda-doubler',
} as const;

/** Props for {@link DoublerFunction}. */
export interface DoublerFunctionProps {
  /**
   * Physical function name. Defaults to `cdk-doubler` (mirroring the demo
   * function's name for standalone/verbatim reuse), but the compat stack
   * ({@link CompatLambdaStack} in iac/cdk/stack.ts) OVERRIDES it to
   * `compat-lambda-doubler` on purpose: MiniStack shares one global namespace,
   * so leaving the default would collide with the demo `cdk-doubler` whenever
   * both are deployed (as in CI). Pass a distinct `compat-*` name in any stack
   * that provisions this construct alongside the demo stack.
   */
  readonly functionName?: string;
}

/**
 * Standalone, reusable hardened "doubler" Lambda — the construct fragment the
 * MiniStack compat harness exposes for the Lambda/CDK vertical (epic #117,
 * sub-issue B / #136).
 *
 * It is a faithful mirror of the `cdk-doubler` function defined inline in
 * `lib/ministack-stack.ts`: same Node 24 runtime, same `lambda/` asset and
 * `index.handler`, same hardening (customer-managed least-privilege role, a
 * KMS-encrypted log group on a rotated CMK, a dead-letter queue on its own
 * rotated CMK, and a reserved-concurrency cap) so it passes cdk-nag
 * (AwsSolutions) and checkov identically.
 *
 * This construct is the reusable building block the vertical PROVISIONS: it is
 * instantiated by {@link CompatLambdaStack} (iac/cdk/stack.ts), which the CDK
 * {@link DeployAdapter} (iac/cdk/deploy.ts) verify-or-provisions against a live
 * MiniStack (#147). It is deliberately NOT added to the demo stack
 * `lib/ministack-stack.ts` — that stays the decoupled "sample", while each
 * compat vertical owns and deploys its own `Compat*Stack` (the sample-vs-proof
 * split). Keeping it out of `lib/` also keeps #136 off the demo CDK snapshot and
 * the cdk-nag/checkov re-verification a live demo-stack change would trigger.
 * The construct documents and proves the hardened doubler-equivalent pattern the
 * harness offers for reuse; it is exercised in full by the pure-synth unit test
 * `test/unit/services/lambda-construct.test.ts`, which holds it under the repo's
 * 100% coverage gate.
 */
export class DoublerFunction extends Construct {
  /** The underlying Lambda function, exposed so callers can grant/wire it. */
  public readonly fn: lambda.Function;

  constructor(scope: Construct, id: string, props: DoublerFunctionProps = {}) {
    super(scope, id);

    const functionName = props.functionName ?? 'cdk-doubler';

    // KMS key to encrypt the Lambda log group (CKV_AWS_158), scoped to this
    // account/region's log group via the CloudWatch Logs encryption-context
    // condition (confused-deputy guard) rather than an unconditional grant.
    const logKey = new kms.Key(this, 'LogKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const logGroupArn = cdk.Stack.of(this).formatArn({
      service: 'logs',
      resource: 'log-group',
      resourceName: `/aws/lambda/${functionName}`,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
    });
    logKey.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [
          new iam.ServicePrincipal(
            `logs.${cdk.Stack.of(this).region}.amazonaws.com`,
          ),
        ],
        actions: [
          'kms:Encrypt*',
          'kms:Decrypt*',
          'kms:ReEncrypt*',
          'kms:GenerateDataKey*',
          'kms:Describe*',
        ],
        resources: ['*'],
        conditions: {
          ArnLike: { 'kms:EncryptionContext:aws:logs:arn': logGroupArn },
        },
      }),
    );

    // Pre-created log group so we can grant write to a concrete resource
    // instead of the AWS-managed AWSLambdaBasicExecutionRole (AwsSolutions-IAM4).
    const logGroup = new logs.LogGroup(this, 'LogGroup', {
      logGroupName: `/aws/lambda/${functionName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      encryptionKey: logKey,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const role = new iam.Role(this, 'Role', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    logGroup.grantWrite(role);

    // Dedicated rotated CMK for the DLQ (unified customer-managed KMS strategy).
    const dlqKey = new kms.Key(this, 'DlqKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    const dlq = new sqs.Queue(this, 'Dlq', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: dlqKey,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.fn = new lambda.Function(this, 'Function', {
      functionName,
      // Provenance marker (#175): the read-back assertion in deploy.ts keys on
      // this exact string so a stale/foreign function of the same name fails
      // loudly instead of letting the integration tier green.
      description: DOUBLER_PROVENANCE_DESCRIPTION,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      // Reuse the same asset the live stack ships (repo-root lambda/).
      code: lambda.Code.fromAsset(
        path.join(__dirname, '..', '..', '..', '..', 'lambda'),
      ),
      role,
      logGroup,
      deadLetterQueue: dlq, // CKV_AWS_116
      reservedConcurrentExecutions: 5, // CKV_AWS_115
    });

    // Secondary provenance marker (#175): a CDK tag scoped to the function.
    cdk.Tags.of(this.fn).add(
      DOUBLER_PROVENANCE_TAG.key,
      DOUBLER_PROVENANCE_TAG.value,
    );
  }
}
