import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { HardenedBucket } from '../../../services/s3/iac/cdk/construct';

// Pure-synth unit test for the reusable S3 construct fragment shipped by the
// compat harness (epic #117, #139). Mirrors
// test/unit/services/lambda-construct.test.ts and test/unit/stack.test.ts:
// synthesize a throwaway stack containing only the construct and assert against
// the resulting CloudFormation template. No AWS, no MiniStack, no Docker.
//
// The construct is under iac/** but NOT named deploy.ts, so it is coverage
// GATED at 100%; this test holds it there.
function synth(): Template {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'ConstructTestStack');
  new HardenedBucket(stack, 'Bucket');
  return Template.fromStack(stack);
}

describe('HardenedBucket construct — fine-grained synth assertions', () => {
  const template = synth();

  it('provisions exactly two buckets (data + dedicated access-log bucket)', () => {
    template.resourceCountIs('AWS::S3::Bucket', 2);
    expect(Object.keys(template.findResources('AWS::S3::Bucket'))).toHaveLength(
      2,
    );
  });

  it('block-all-public-access on both buckets', () => {
    const buckets = template.findResources('AWS::S3::Bucket');
    for (const bucket of Object.values(buckets)) {
      expect(bucket.Properties.PublicAccessBlockConfiguration).toEqual({
        BlockPublicAcls: true,
        BlockPublicPolicy: true,
        IgnorePublicAcls: true,
        RestrictPublicBuckets: true,
      });
    }
  });

  it('server-side encryption + versioning on both buckets', () => {
    const buckets = template.findResources('AWS::S3::Bucket');
    for (const bucket of Object.values(buckets)) {
      expect(bucket.Properties.BucketEncryption).toBeDefined();
      expect(bucket.Properties.VersioningConfiguration).toEqual({
        Status: 'Enabled',
      });
    }
  });

  it('enforces SSL via a deny-non-TLS bucket policy on both buckets', () => {
    const policies = template.findResources('AWS::S3::BucketPolicy');
    // One policy per bucket (data + log).
    expect(Object.keys(policies)).toHaveLength(2);
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

  it('the data bucket ships access logs to the dedicated log bucket', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      LoggingConfiguration: Match.objectLike({
        LogFilePrefix: 'data-bucket/',
      }),
    });
    // Companion literal assertion (SonarQube S2699 — CDK matchers aren't
    // counted): the data bucket's LoggingConfiguration.LogFilePrefix is exactly
    // 'data-bucket/', proving it ships access logs (to the dedicated log bucket,
    // which carries a DestinationBucketName ref rather than the self-log prefix).
    const prefixes = Object.values(template.findResources('AWS::S3::Bucket'))
      .map((b) => b.Properties.LoggingConfiguration?.LogFilePrefix)
      .sort();
    expect(prefixes).toEqual(['data-bucket/', 'self/']);
  });

  it('the log bucket logs to itself (self/ prefix), avoiding an infinite chain', () => {
    template.hasResourceProperties('AWS::S3::Bucket', {
      LoggingConfiguration: Match.objectLike({
        LogFilePrefix: 'self/',
      }),
    });
    // Companion literal assertion (SonarQube S2699). Exactly one bucket logs to
    // itself under the 'self/' prefix — the log bucket — which is what breaks the
    // otherwise-infinite chain of log buckets each needing their own log bucket.
    const selfLoggers = Object.values(
      template.findResources('AWS::S3::Bucket'),
    ).filter(
      (b) => b.Properties.LoggingConfiguration?.LogFilePrefix === 'self/',
    );
    expect(selfLoggers).toHaveLength(1);
  });

  it('bounds accumulation with lifecycle rules on both buckets', () => {
    const buckets = template.findResources('AWS::S3::Bucket');
    for (const bucket of Object.values(buckets)) {
      expect(bucket.Properties.LifecycleConfiguration).toBeDefined();
      expect(
        bucket.Properties.LifecycleConfiguration.Rules.length,
      ).toBeGreaterThan(0);
    }
  });

  it('names the data bucket cdk-demo-bucket by default with a -logs sibling', () => {
    const names = Object.values(template.findResources('AWS::S3::Bucket'))
      .map((b) => b.Properties.BucketName)
      .sort();
    expect(names).toEqual(['cdk-demo-bucket', 'cdk-demo-bucket-logs']);
  });

  it('honors an explicit bucketName prop (and derives the log bucket name)', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'NamedStack');
    new HardenedBucket(stack, 'Named', { bucketName: 'my-data' });
    const named = Template.fromStack(stack);
    const names = Object.values(named.findResources('AWS::S3::Bucket'))
      .map((b) => b.Properties.BucketName)
      .sort();
    expect(names).toEqual(['my-data', 'my-data-logs']);
  });

  it('exposes the underlying data s3.Bucket so callers can wire it up', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'HandleStack');
    const hardened = new HardenedBucket(stack, 'Handle');
    // The public `bucket` handle is a real S3 bucket construct.
    expect(hardened.bucket.bucketArn).toBeDefined();
    expect(hardened.bucket.bucketName).toBeDefined();
  });
});
