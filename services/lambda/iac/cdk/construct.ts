import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as path from 'node:path';

/** Props for {@link DoublerFunction}. */
export interface DoublerFunctionProps {
  /**
   * Physical function name. Defaults to `cdk-doubler` so a stack that adopts
   * this construct verbatim matches the name the harness's CDK
   * {@link DeployAdapter} (iac/cdk/deploy.ts) short-circuits to.
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
 * This construct is ADDITIVE: it is NOT wired into the deployed
 * `MiniStackStack`. The vertical's CDK adapter short-circuits to the
 * already-deployed `cdk-doubler`, so the live stack is untouched (which keeps
 * #136 off `lib/`, the CDK snapshot, and the cdk-nag/checkov re-verification of
 * a stack change). The construct documents and proves the hardened
 * doubler-equivalent pattern the harness offers for reuse; it is exercised in
 * full by the pure-synth unit test `test/unit/services/lambda-construct.test.ts`,
 * which holds it under the repo's 100% coverage gate.
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
  }
}
