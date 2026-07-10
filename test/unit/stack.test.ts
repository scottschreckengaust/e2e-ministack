import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
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
    // Companion assertion so SonarQube (S2699) sees an explicit assertion:
    // the CDK matcher above throws on mismatch, this restates the count.
    expect(Object.keys(template.findResources('AWS::S3::Bucket')).length).toBe(
      2,
    );
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
    expect(
      Object.keys(template.findResources('AWS::S3::Bucket')).length,
    ).toBeGreaterThan(0);
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
    expect(
      Object.keys(template.findResources('AWS::S3::BucketPolicy')).length,
    ).toBeGreaterThan(0);
  });

  it('deploys the Lambda on the nodejs24.x runtime', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'cdk-doubler',
      Runtime: 'nodejs24.x',
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('configures the Lambda with a dead-letter queue and reserved concurrency', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      DeadLetterConfig: Match.objectLike({ TargetArn: Match.anyValue() }),
      ReservedConcurrentExecutions: 5,
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('encrypts the DLQ with a customer-managed CMK (unified KMS strategy)', () => {
    // issue #34: the DLQ previously used the AWS-managed aws/sqs key
    // (KMS_MANAGED). It now uses a customer-managed CMK with rotation, matching
    // the log group's strategy. KmsMasterKeyId references the CMK's key ARN
    // (not the literal 'alias/aws/sqs' string that KMS_MANAGED emits).
    template.hasResourceProperties('AWS::SQS::Queue', {
      KmsMasterKeyId: Match.objectLike({ 'Fn::GetAtt': Match.anyValue() }),
    });
    // A dedicated rotation-enabled CMK exists for the DLQ (in addition to the
    // log-group key): assert at least two rotated CMKs are present.
    const keys = template.findResources('AWS::KMS::Key');
    const rotated = Object.values(keys).filter(
      (k) => k.Properties.EnableKeyRotation === true,
    );
    expect(rotated.length).toBeGreaterThanOrEqual(2);
  });

  it('alarms on DLQ depth so failed invocations are observable', () => {
    // issue #34: without an alarm, failed async invocations accumulate in the
    // DLQ silently. Assert a CloudWatch alarm watches the queue's
    // ApproximateNumberOfMessagesVisible metric and breaches above 0.
    template.hasResourceProperties('AWS::CloudWatch::Alarm', {
      Namespace: 'AWS/SQS',
      MetricName: 'ApproximateNumberOfMessagesVisible',
      ComparisonOperator: 'GreaterThanThreshold',
      Threshold: 0,
      EvaluationPeriods: 1,
      TreatMissingData: 'notBreaching',
    });
    expect(
      Object.keys(template.findResources('AWS::CloudWatch::Alarm')).length,
    ).toBeGreaterThan(0);
  });

  it('KMS-encrypts the Lambda log group', () => {
    template.hasResourceProperties('AWS::Logs::LogGroup', {
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 7,
    });
    expect(
      Object.keys(template.findResources('AWS::Logs::LogGroup')).length,
    ).toBeGreaterThan(0);
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
    expect(
      Object.keys(template.findResources('AWS::KMS::Key')).length,
    ).toBeGreaterThan(0);
  });

  it('does not attach the AWS-managed AWSLambdaBasicExecutionRole', () => {
    const roles = template.findResources('AWS::IAM::Role');
    const json = JSON.stringify(roles);
    expect(json).not.toContain('AWSLambdaBasicExecutionRole');
  });
});

describe('MiniStackStack — cdk-nag (AwsSolutions) fast-tier gate', () => {
  it('synthesizes with zero unsuppressed AwsSolutions findings', () => {
    // issue #25: bin/app.ts attaches the AwsSolutions pack via the cdk-nag v3
    // policy-validation API (Validations.of(app).addPlugins(...)), but that
    // gate only fires inside the CDK CLI's `cdk synth` — an in-process
    // `app.synth()` does NOT enforce it. So the unit tier (its own `new
    // cdk.App()` with no plugin) never exercised cdk-nag; a nag regression
    // would only surface in CI synth, not the fast tier.
    //
    // We drive the SAME pack class used in bin/app.ts directly via its
    // documented testing entry point `validateScope(stack)` (cdk-nag v3 removed
    // the v2 Aspects `visit` API, and `Annotations.fromStack` no longer sees
    // nag findings). A clean stack reports `success: true` with no violations;
    // injecting an unhardened resource flips `success` to false (verified
    // manually with a bare Bucket → AwsSolutions-S1/S10). This makes a nag
    // regression fail fast in unit, not only in CI synth.
    const app = new cdk.App();
    const stack = new MiniStackStack(app, 'NagTestStack', {
      env: MINISTACK_ENV,
    });
    app.synth();

    const report = new AwsSolutionsChecks(stack, {
      verbose: true,
    }).validateScope(stack);
    const findings = report.violations.map(
      (v) => `${v.ruleName}: ${v.description}`,
    );
    expect(findings).toEqual([]);
    expect(report.success).toBe(true);
  });
});
