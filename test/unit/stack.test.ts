import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { MiniStackStack } from '../../lib/ministack-stack';

// Pure-synth CDK tests — no AWS, no MiniStack, no Docker. Synthesize the stack
// to a CloudFormation template and assert against it.
function synth(): Template {
  const app = new cdk.App();
  const stack = new MiniStackStack(app, 'TestStack', {
    env: { account: '000000000000', region: 'us-east-1' },
  });
  return Template.fromStack(stack);
}

describe('MiniStackStack — fine-grained assertions', () => {
  const template = synth();

  it('creates exactly two S3 buckets (data + logs)', () => {
    template.resourceCountIs('AWS::S3::Bucket', 2);
  });

  it('data + log buckets block all public access', () => {
    // Both buckets must have the full block-public-access configuration.
    const buckets = template.findResources('AWS::S3::Bucket');
    for (const id of Object.keys(buckets)) {
      expect(buckets[id].Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      });
    }
  });

  it('buckets enforce TLS via a deny-insecure-transport policy', () => {
    template.hasResourceProperties('AWS::S3::BucketPolicy', {
      PolicyDocument: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Effect: 'Deny',
            Condition: { Bool: { 'aws:SecureTransport': 'false' } },
          }),
        ]),
      }),
    });
  });

  it('deploys the Lambda on the nodejs24.x runtime', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'cdk-doubler',
      Runtime: 'nodejs24.x',
    });
  });

  it('configures the Lambda with a dead-letter queue and reserved concurrency', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      DeadLetterConfig: Match.objectLike({ TargetArn: Match.anyValue() }),
      ReservedConcurrentExecutions: 5,
    });
  });

  it('KMS-encrypts the Lambda log group', () => {
    template.hasResourceProperties('AWS::Logs::LogGroup', {
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 7,
    });
  });

  it('does not attach the AWS-managed AWSLambdaBasicExecutionRole', () => {
    const roles = template.findResources('AWS::IAM::Role');
    const json = JSON.stringify(roles);
    expect(json).not.toContain('AWSLambdaBasicExecutionRole');
  });
});

describe('MiniStackStack — snapshot', () => {
  it('matches the synthesized CloudFormation snapshot', () => {
    // Regression tripwire: any change to the synthesized template must be
    // reviewed and the snapshot updated with `npm run test:unit -- -u`.
    expect(synth().toJSON()).toMatchSnapshot();
  });
});
