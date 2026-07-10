import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as cloudwatch from 'aws-cdk-lib/aws-cloudwatch';
import * as path from 'node:path';

/**
 * Minimal end-to-end stack: an S3 bucket and a Lambda function.
 *
 * Hardened to pass both cdk-nag (AwsSolutions) and checkov:
 *  - S3: TLS enforced, SSE, block-public, versioning, access logging.
 *  - Lambda: customer-managed least-privilege role, KMS-encrypted log group,
 *    dead-letter queue, and a reserved concurrency limit.
 *
 * Resource names are fixed (bucketName / functionName) so the integration
 * tests can address them without reading CloudFormation outputs. In a real
 * stack you would prefer CfnOutputs + describe-stacks; fixed names keep the
 * example self-contained.
 *
 * WARNING — do NOT deploy this stack unchanged to a real AWS account. S3 bucket
 * names are GLOBALLY unique across every AWS account and region, so the
 * hard-coded 'cdk-demo-bucket' / 'cdk-demo-log-bucket' names below will almost
 * certainly collide with a bucket someone else already owns and fail the deploy
 * with "BucketAlreadyExists" (issue #35). The fixed names are deliberate here
 * only because everything runs against the local MiniStack emulator, which
 * isolates the global namespace. For a real-account deploy, either drop the
 * explicit `bucketName` (let CDK auto-generate a unique, account/region-scoped
 * name) or parameterize it with a deployer-supplied prefix — and switch the
 * tests to read CfnOutputs instead of the hard-coded names.
 */
export class MiniStackStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Dedicated bucket to receive the data bucket's server access logs
    // (AwsSolutions-S1 / CKV_AWS_18). It logs to itself to avoid an infinite
    // chain of log buckets.
    const logBucket = new s3.Bucket(this, 'LogBucket', {
      bucketName: 'cdk-demo-log-bucket',
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true, // CKV_AWS_21
      serverAccessLogsPrefix: 'self/', // CKV_AWS_18 (logs to itself)
      // Versioned + DESTROY without lifecycle rules lets noncurrent versions,
      // aborted multipart uploads, and the self-ingested access logs grow
      // unboundedly (issue #6). Bound all three (CKV_AWS_300):
      //  - drop noncurrent versions after 30d (superseded log data has no
      //    audit value), keeping 1 prior version as a short safety net;
      //  - abort incomplete multipart uploads after 7d;
      //  - expire the self/ access logs after 90d (typical short retention
      //    window for operational access logs).
      lifecycleRules: [
        {
          id: 'expire-noncurrent-versions',
          noncurrentVersionExpiration: cdk.Duration.days(30),
          noncurrentVersionsToRetain: 1,
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
        {
          id: 'expire-access-logs',
          prefix: 'self/',
          expiration: cdk.Duration.days(90),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Data bucket: no autoDeleteObjects custom resource, which doesn't
    // complete cleanly against the emulator. Use `cdk destroy` +
    // POST /_ministack/reset to clean up between runs instead.
    new s3.Bucket(this, 'DataBucket', {
      bucketName: 'cdk-demo-bucket',
      enforceSSL: true, // AwsSolutions-S10
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      versioned: true, // CKV_AWS_21
      serverAccessLogsBucket: logBucket, // AwsSolutions-S1 / CKV_AWS_18
      serverAccessLogsPrefix: 'data-bucket/',
      // Bound noncurrent-version and multipart-upload accumulation (issue #6 /
      // CKV_AWS_300). Same rationale as the log bucket; no object-expiration
      // rule since live data has no fixed retention here.
      lifecycleRules: [
        {
          id: 'expire-noncurrent-versions',
          noncurrentVersionExpiration: cdk.Duration.days(30),
          noncurrentVersionsToRetain: 1,
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const functionName = 'cdk-doubler';

    // KMS key to encrypt the Lambda log group (CKV_AWS_158). The key policy
    // must let the CloudWatch Logs service in this region use the key.
    const logKey = new kms.Key(this, 'DoublerLogKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    // Confused-deputy guard: scope the grant to the single Lambda log group via
    // an ArnLike condition on the kms:EncryptionContext:aws:logs:arn key. CloudWatch
    // Logs passes the target log-group ARN as encryption context, so this restricts
    // the service principal to using the key only on this account/region's
    // /aws/lambda/cdk-doubler log group (AWS's documented CMK-for-single-log-group
    // pattern), instead of an unconditional Resource:'*' grant.
    const logGroupArn = cdk.Stack.of(this).formatArn({
      service: 'logs',
      resource: 'log-group',
      resourceName: `/aws/lambda/${functionName}`,
      arnFormat: cdk.ArnFormat.COLON_RESOURCE_NAME,
    });
    logKey.addToResourcePolicy(
      new iam.PolicyStatement({
        principals: [
          new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`),
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
          ArnLike: {
            'kms:EncryptionContext:aws:logs:arn': logGroupArn,
          },
        },
      }),
    );

    // Pre-create the function's log group so we can grant write access to a
    // concrete resource instead of the AWS-managed AWSLambdaBasicExecutionRole
    // (AwsSolutions-IAM4). KMS-encrypted (CKV_AWS_158) with retention.
    const logGroup = new logs.LogGroup(this, 'DoublerLogGroup', {
      logGroupName: `/aws/lambda/${functionName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      encryptionKey: logKey,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const role = new iam.Role(this, 'DoublerRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    // grantWrite scopes to this log group's own ARN (no AWS-managed policy,
    // no broad wildcard resource — clears AwsSolutions-IAM4/IAM5).
    logGroup.grantWrite(role);

    // Unified KMS strategy: this stack uses customer-managed CMKs (with key
    // rotation) everywhere it encrypts, rather than mixing customer-managed and
    // AWS-managed keys. The log group above uses a CMK; the DLQ previously used
    // sqs.QueueEncryption.KMS_MANAGED (the aws/sqs AWS-managed alias), so two
    // encryption philosophies sat side by side (issue #34). We give the DLQ its
    // own dedicated CMK so both data stores share one consistent, rotated,
    // policy-controllable key strategy. A separate key (rather than reusing the
    // log key) keeps each key's resource policy scoped to a single purpose.
    const dlqKey = new kms.Key(this, 'DoublerDlqKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Dead-letter queue for failed async invocations (CKV_AWS_116),
    // encrypted with the customer-managed CMK above and TLS-enforced.
    const dlq = new sqs.Queue(this, 'DoublerDlq', {
      encryption: sqs.QueueEncryption.KMS,
      encryptionMasterKey: dlqKey,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Observability: failed async invocations land in the DLQ silently
    // (issue #34). Alarm on any visible message so a failure surfaces instead of
    // accumulating unnoticed. Threshold > 0 over a single 1-minute period;
    // missing data (an idle, empty queue) is treated as not-breaching.
    new cloudwatch.Alarm(this, 'DoublerDlqDepthAlarm', {
      alarmName: `${functionName}-dlq-depth`,
      alarmDescription:
        'Dead-letter queue for cdk-doubler has visible messages: a failed async invocation needs investigation.',
      metric: dlq.metricApproximateNumberOfMessagesVisible({
        period: cdk.Duration.minutes(1),
        statistic: cloudwatch.Stats.MAXIMUM,
      }),
      threshold: 0,
      comparisonOperator: cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
      evaluationPeriods: 1,
      treatMissingData: cloudwatch.TreatMissingData.NOT_BREACHING,
    });

    // NODEJS_24_X was added in aws-cdk-lib 2.230.0 (pinned in package.json).
    const fn = new lambda.Function(this, 'Doubler', {
      functionName,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      role,
      logGroup,
      deadLetterQueue: dlq, // CKV_AWS_116
      reservedConcurrentExecutions: 5, // CKV_AWS_115
    });

    // CKV_AWS_117 (Lambda-in-VPC) is intentionally skipped: this demo function
    // calls no private resources, and putting it in a VPC would add ENIs/NAT
    // with no security benefit here. Inject the checkov skip into the synthesized
    // resource's CloudFormation Metadata so it survives every synth.
    const cfnFn = fn.node.defaultChild as lambda.CfnFunction;
    cfnFn.addMetadata('checkov', {
      skip: [
        {
          id: 'CKV_AWS_117',
          comment:
            'Demo Lambda accesses no VPC-private resources; a VPC adds ENI/NAT overhead with no security benefit.',
        },
      ],
    });
  }
}
