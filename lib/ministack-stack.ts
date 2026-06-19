import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as path from 'path';

/**
 * Minimal end-to-end stack: an S3 bucket and a Lambda function.
 *
 * Resource names are fixed (bucketName / functionName) so the integration
 * tests can address them without reading CloudFormation outputs. In a real
 * stack you would prefer CfnOutputs + describe-stacks; fixed names keep the
 * example self-contained.
 */
export class MiniStackStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Plain bucket: no autoDeleteObjects custom resource, which doesn't
    // complete cleanly against the emulator. Use `cdk destroy` +
    // POST /_ministack/reset to clean up between runs instead.
    new s3.Bucket(this, 'DataBucket', {
      bucketName: 'cdk-demo-bucket',
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    // NODEJS_24_X was added in aws-cdk-lib 2.230.0 (pinned in package.json).
    new lambda.Function(this, 'Doubler', {
      functionName: 'cdk-doubler',
      runtime: lambda.Runtime.NODEJS_24_X,
      handler: 'index.handler',
      code: lambda.Code.fromAsset(path.join(__dirname, '..', 'lambda')),
    });
  }
}
