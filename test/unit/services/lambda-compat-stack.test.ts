import * as cdk from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import {
  CompatLambdaStack,
  COMPAT_LAMBDA_FUNCTION_NAME,
} from '../../../services/lambda/iac/cdk/stack';
import { buildCompatApp } from '../../../services/lambda/iac/cdk/app';
import { MINISTACK_ENV } from '../../../lib/env';

// Pure-synth unit test for the Lambda/CDK vertical's self-provisioned compat
// stack + app entrypoint (epic #117, #147). Mirrors test/unit/stack.test.ts and
// test/unit/services/lambda-construct.test.ts: synthesize to CloudFormation and
// assert against the template — no AWS, no MiniStack, no Docker.
//
// stack.ts and app.ts are under services/ but are NOT checks.*.ts, deploy.ts,
// or *.test.ts, so jest.config.js holds them at the repo's 100% coverage gate.
// This test exercises them in full so they stay there. The adapter's
// integration-tier provisioner (iac/cdk/deploy.ts) is coverage-excluded by the
// path convention and proven instead by the CI Integration job / the
// fresh-MiniStack demonstration on the PR.
describe('CompatLambdaStack — self-provisioned compat stack', () => {
  function synth(): Template {
    const app = new cdk.App();
    const stack = new CompatLambdaStack(app, 'CompatLambdaStack');
    return Template.fromStack(stack);
  }

  const template = synth();

  it('names the function compat-lambda-doubler (distinct from the demo cdk-doubler)', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'compat-lambda-doubler',
      Runtime: 'nodejs24.x',
      Handler: 'index.handler',
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('keeps the compat function name DISTINCT from the demo cdk-doubler (collision guard)', () => {
    // The whole point of the distinct name is that MiniStack shares one global
    // namespace: a compat stack reusing the demo `cdk-doubler` (the
    // DoublerFunction default) would collide with lib/ministack-stack.ts
    // whenever both are deployed (as in CI). This invariant is otherwise only
    // convention — lock it so a future edit that "simplifies" back to the
    // default name fails here rather than in a confusing MiniStack collision.
    // Mirrors the two-bucket guard in test/unit/stack.test.ts.
    expect(COMPAT_LAMBDA_FUNCTION_NAME).not.toBe('cdk-doubler');
  });

  it('carries the hardened DoublerFunction shape (DLQ + reserved concurrency)', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      ReservedConcurrentExecutions: 5,
    });
    template.resourceCountIs('AWS::SQS::Queue', 1);
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
    // The DLQ that backs the reserved-concurrency hardening.
    expect(Object.keys(template.findResources('AWS::SQS::Queue'))).toHaveLength(
      1,
    );
  });

  it('pins the deploy target to the MiniStack account/region unconditionally', () => {
    const app = new cdk.App();
    const stack = new CompatLambdaStack(app, 'CompatLambdaStack');
    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });
});

describe('CompatLambdaStack — cdk-nag (AwsSolutions) fast-tier gate', () => {
  it('synthesizes with zero unsuppressed AwsSolutions findings', () => {
    // Parity with test/unit/stack.test.ts:169-200. bin/app.ts and the compat
    // app.ts attach the AwsSolutions pack via the cdk-nag v3 policy-validation
    // API (Validations.of(app).addPlugins(...)), but that gate only fires
    // inside the CDK CLI's `cdk synth`. We drive the SAME pack class directly
    // via its documented `validateScope(stack)` entry point so a nag regression
    // in the compat stack fails fast in the unit tier, not only in CI synth.
    const app = new cdk.App();
    const stack = new CompatLambdaStack(app, 'NagCompatLambdaStack');
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
  it('instantiates the CompatLambdaStack pinned to the MiniStack env', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatLambdaStack') as cdk.Stack;

    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });

  it('synthesizes the compat-lambda-doubler function through the app', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatLambdaStack') as cdk.Stack;
    const template = Template.fromStack(stack);
    template.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'compat-lambda-doubler',
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('attaches the cdk-nag AwsSolutions pack to the app (so `cdk synth` gates)', () => {
    // The cdk-nag "zero findings" test above drives the pack class DIRECTLY,
    // so it passes even if app.ts forgot to register the pack — meaning the
    // one line that makes the CLI's `cdk synth` actually enforce cdk-nag on
    // the compat stack (Validations.of(app).addPlugins(new AwsSolutionsChecks
    // (...))) was executed-but-not-ASSERTED: deleting it kept every test green
    // at 100% coverage. Assert the effect here — the app must carry the pack as
    // a registered policy-validation plugin. `policyValidationBeta1` is the
    // typed public getter cdk populates from addPlugins(); AwsSolutionsChecks
    // reports itself as the 'AwsSolutions' plugin. If app.ts drops the
    // addPlugins call, this array is empty and the test fails.
    const app = buildCompatApp();
    const pluginNames = app.policyValidationBeta1.map((p) => p.name);
    expect(pluginNames).toContain('AwsSolutions');
  });
});
