import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as logs from 'aws-cdk-lib/aws-logs';
import * as path from 'path';

/**
 * Minimal end-to-end stack: an S3 bucket and a Lambda function.
 *
 * Hardened to pass cdk-nag's AwsSolutions pack:
 *  - S3 server access logging (AwsSolutions-S1)
 *  - enforced TLS (AwsSolutions-S10)
 *  - S3-managed encryption at rest
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
    // (satisfies AwsSolutions-S1). It logs to itself to avoid an infinite
    // chain of log buckets.
    const logBucket = new s3.Bucket(this, 'LogBucket', {
      bucketName: 'cdk-demo-log-bucket',
      enforceSSL: true,
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // Plain data bucket: no autoDeleteObjects custom resource, which doesn't
    // complete cleanly against the emulator. Use `cdk destroy` +
    // POST /_ministack/reset to clean up between runs instead.
    new s3.Bucket(this, 'DataBucket', {
      bucketName: 'cdk-demo-bucket',
      enforceSSL: true, // AwsSolutions-S10
      encryption: s3.BucketEncryption.S3_MANAGED,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      serverAccessLogsBucket: logBucket, // AwsSolutions-S1
      serverAccessLogsPrefix: 'data-bucket/',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const functionName = 'cdk-doubler';

    // Pre-create the function's log group so we can grant write access to a
    // concrete resource instead of the AWS-managed AWSLambdaBasicExecutionRole
    // (which AwsSolutions-IAM4 flags). Explicit role + scoped grant keeps this
    // least-privilege.
    const logGroup = new logs.LogGroup(this, 'DoublerLogGroup', {
      logGroupName: `/aws/lambda/${functionName}`,
      retention: logs.RetentionDays.ONE_WEEK,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const role = new iam.Role(this, 'DoublerRole', {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
    });
    // grantWrite scopes to this log group's own ARN (no AWS-managed policy,
    // no broad wildcard resource).
    logGroup.grantWrite(role);

    // NODEJS_24_X was added in aws-cdk-lib 2.230.0 (pinned in package.json).
    new lambda.Function(this, 'Doubler', {
      functionName,
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
      role,
      logGroup,
    });
  }
}
