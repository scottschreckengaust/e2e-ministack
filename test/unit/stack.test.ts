import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { MiniStackStack } from '../../lib/ministack-stack';
import { MINISTACK_ENV } from '../../lib/env';

// Pure-synth CDK tests — no AWS, no MiniStack, no Docker. Synthesize the stack
// to a CloudFormation template and assert against it.
function synth(): Template {
  const app = new cdk.App();
  const stack = new MiniStackStack(app, 'TestStack', { env: MINISTACK_ENV });
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

  it('both buckets bound version/upload growth with lifecycle rules', () => {
    // issue #6: versioned + DESTROY buckets must not accumulate noncurrent
    // versions or aborted multipart uploads unboundedly. Both buckets share
    // the expire-noncurrent-versions rule.
    const buckets = template.findResources('AWS::S3::Bucket');
    for (const id of Object.keys(buckets)) {
      const rules = buckets[id].Properties.LifecycleConfiguration.Rules;
      expect(rules).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            Id: 'expire-noncurrent-versions',
            Status: 'Enabled',
            NoncurrentVersionExpiration: {
              NoncurrentDays: 30,
              NewerNoncurrentVersions: 1,
            },
            AbortIncompleteMultipartUpload: { DaysAfterInitiation: 7 },
          }),
        ]),
      );
    }
  });

  it('the log bucket expires its self-ingested access logs', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      BucketName: 'cdk-demo-log-bucket',
      LifecycleConfiguration: {
        Rules: Match.arrayWith([
          Match.objectLike({
            Id: 'expire-access-logs',
            Status: 'Enabled',
            Prefix: 'self/',
            ExpirationInDays: 90,
          }),
        ]),
      },
    });
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

  it('scopes the CloudWatch Logs KMS grant with a confused-deputy condition', () => {
    // The grant to logs.<region>.amazonaws.com must be constrained by an
    // ArnLike condition on kms:EncryptionContext:aws:logs:arn = the specific
    // Lambda log-group ARN (AWS's documented CMK-for-single-log-group pattern),
    // not left as an unconditional Resource:'*' grant.
    template.hasResourceProperties('AWS::KMS::Key', {
      KeyPolicy: Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: { Service: 'logs.us-east-1.amazonaws.com' },
            Condition: {
              ArnLike: {
                'kms:EncryptionContext:aws:logs:arn': {
                  'Fn::Join': Match.anyValue(),
                },
              },
            },
          }),
        ]),
      }),
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
    //
    // Mask the Lambda asset's content hash (Code.S3Key) — it's the SHA-256 of
    // the zipped `lambda/` dir, so it flips on any lambda/index.js edit even
    // when the template is otherwise unchanged. Pinning it would make this
    // infra snapshot fail for code-only changes and train reviewers to
    // rubber-stamp `-u`. The S3Bucket alongside it is the stable CDK bootstrap
    // bucket, so it stays asserted.
    expect(synth().toJSON()).toMatchSnapshot({
      Resources: {
        Doubler90AA16BC: {
          Properties: { Code: { S3Key: expect.any(String) } },
        },
      },
    });
  });
});
