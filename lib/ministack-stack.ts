import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as kms from 'aws-cdk-lib/aws-kms';
import * as sqs from 'aws-cdk-lib/aws-sqs';
import * as path from 'path';

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
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const functionName = 'cdk-doubler';

    // KMS key to encrypt the Lambda log group (CKV_AWS_158). The key policy
    // must let the CloudWatch Logs service in this region use the key.
    const logKey = new kms.Key(this, 'DoublerLogKey', {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
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

    // Dead-letter queue for failed async invocations (CKV_AWS_116),
    // KMS-encrypted and TLS-enforced.
    const dlq = new sqs.Queue(this, 'DoublerDlq', {
      encryption: sqs.QueueEncryption.KMS_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
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
