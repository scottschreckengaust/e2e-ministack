import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import {
  CompatS3Stack,
  COMPAT_S3_BUCKET_NAME,
} from '../../../services/s3/iac/cdk/stack';
import { buildCompatApp } from '../../../services/s3/iac/cdk/app';
import { MINISTACK_ENV } from '../../../lib/env';

// Pure-synth unit test for the S3/CDK vertical's self-provisioned compat stack +
// app entrypoint (epic #117, #139). Mirrors
// test/unit/services/lambda-compat-stack.test.ts: synthesize to CloudFormation
// and assert against the template — no AWS, no MiniStack, no Docker.
//
// stack.ts and app.ts are under services/ but are NOT checks.*.ts, deploy.ts,
// or *.test.ts, so jest.config.js holds them at the repo's 100% coverage gate.
// This test exercises them in full so they stay there. The adapter's
// integration-tier provisioner (iac/cdk/deploy.ts) is coverage-excluded by the
// path convention and proven instead by the CI Integration job.
describe('CompatS3Stack — self-provisioned compat stack', () => {
  function synth(): Template {
    const app = new cdk.App();
    const stack = new CompatS3Stack(app, 'CompatS3Stack');
    return Template.fromStack(stack);
  }

  const template = synth();

  it('names the data bucket compat-s3-bucket (distinct from the demo cdk-demo-bucket)', () => {
    const names = Object.values(template.findResources('AWS::S3::Bucket'))
      .map((b) => b.Properties.BucketName)
      .sort();
    expect(names).toEqual(['compat-s3-bucket', 'compat-s3-bucket-logs']);
  });

  it('keeps the compat bucket name DISTINCT from the demo cdk-demo-bucket (collision guard)', () => {
    // The whole point of the distinct name is that MiniStack shares one global
    // namespace: a compat stack reusing the demo `cdk-demo-bucket` (the
    // HardenedBucket default) would collide with lib/ministack-stack.ts whenever
    // both are deployed (as in CI). This invariant is otherwise only convention
    // — lock it so a future edit that "simplifies" back to the default name
    // fails here rather than in a confusing MiniStack collision. Mirrors the
    // two-bucket guard in test/unit/stack.test.ts.
    expect(COMPAT_S3_BUCKET_NAME).not.toBe('cdk-demo-bucket');
  });

  it('carries the hardened two-bucket shape (data + dedicated access-log bucket)', () => {
    template.resourceCountIs('AWS::S3::Bucket', 2);
    // A deny-non-TLS bucket policy per bucket proves the SSL hardening survived.
    template.resourceCountIs('AWS::S3::BucketPolicy', 2);
  });

  it('pins the deploy target to the MiniStack account/region unconditionally', () => {
    const app = new cdk.App();
    const stack = new CompatS3Stack(app, 'CompatS3Stack');
    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });
});

describe('CompatS3Stack — cdk-nag (AwsSolutions) fast-tier gate', () => {
  it('synthesizes with zero unsuppressed AwsSolutions findings', () => {
    // Parity with test/unit/services/lambda-compat-stack.test.ts. bin/app.ts and
    // the compat app.ts attach the AwsSolutions pack via the cdk-nag v3
    // policy-validation API (Validations.of(app).addPlugins(...)), but that gate
    // only fires inside the CDK CLI's `cdk synth`. We drive the SAME pack class
    // directly via its documented `validateScope(stack)` entry point so a nag
    // regression in the compat stack fails fast in the unit tier, not only in CI
    // synth.
    const app = new cdk.App();
    const stack = new CompatS3Stack(app, 'NagCompatS3Stack');
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

describe('buildCompatApp — per-vertical CDK app entrypoint', () => {
  it('instantiates the CompatS3Stack pinned to the MiniStack env', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatS3Stack') as cdk.Stack;

    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });

  it('synthesizes the compat-s3-bucket through the app', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatS3Stack') as cdk.Stack;
    const template = Template.fromStack(stack);
    const names = Object.values(template.findResources('AWS::S3::Bucket')).map(
      (b) => b.Properties.BucketName,
    );
    expect(names).toContain('compat-s3-bucket');
  });

  it('attaches the cdk-nag AwsSolutions pack to the app (so `cdk synth` gates)', () => {
    // The cdk-nag "zero findings" test above drives the pack class DIRECTLY, so
    // it passes even if app.ts forgot to register the pack — meaning the one line
    // that makes the CLI's `cdk synth` actually enforce cdk-nag on the compat
    // stack (Validations.of(app).addPlugins(new AwsSolutionsChecks(...))) was
    // executed-but-not-ASSERTED: deleting it kept every test green at 100%
    // coverage. Assert the effect here — the app must carry the pack as a
    // registered policy-validation plugin. Mirrors the Lambda vertical's test.
    const app = buildCompatApp();
    const pluginNames = app.policyValidationBeta1.map((p) => p.name);
    expect(pluginNames).toContain('AwsSolutions');
  });
});
