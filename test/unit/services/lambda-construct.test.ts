import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import {
  DoublerFunction,
  DOUBLER_PROVENANCE_DESCRIPTION,
  DOUBLER_PROVENANCE_TAG,
} from '../../../services/lambda/iac/cdk/construct';

// Pure-synth unit test for the reusable Lambda construct fragment shipped by
// the compat harness (epic #117, sub-issue B / #136). Mirrors
// test/unit/stack.test.ts: synthesize a throwaway stack containing only the
// construct and assert against the resulting CloudFormation template. No AWS,
// no MiniStack, no Docker.
//
// The Axis-2 CDK adapter (iac/cdk/deploy.ts) short-circuits to the already
// deployed `cdk-doubler` from lib/ministack-stack.ts, so this construct is not
// wired into the deployed stack — it documents and proves the hardened
// doubler-equivalent construct the harness exposes for reuse by later
// verticals. It is under iac/** but NOT named deploy.ts, so it is coverage
// GATED at 100%; this test holds it there.
function synth(): Template {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'ConstructTestStack');
  new DoublerFunction(stack, 'Doubler');
  return Template.fromStack(stack);
}

describe('DoublerFunction construct — fine-grained synth assertions', () => {
  const template = synth();

  it('deploys a Lambda on the nodejs24.x runtime with the doubler handler', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Runtime: 'nodejs24.x',
      Handler: 'index.handler',
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('hardens the Lambda with a dead-letter queue and reserved concurrency', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      DeadLetterConfig: Match.objectLike({ TargetArn: Match.anyValue() }),
      ReservedConcurrentExecutions: 5,
    });
    expect(
      Object.keys(template.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('KMS-encrypts the Lambda log group with a rotated CMK', () => {
    template.hasResourceProperties('AWS::Logs::LogGroup', {
      KmsKeyId: Match.anyValue(),
      RetentionInDays: 7,
    });
    const keys = template.findResources('AWS::KMS::Key');
    const rotated = Object.values(keys).filter(
      (k) => k.Properties.EnableKeyRotation === true,
    );
    // One CMK for the log group + one for the DLQ, both rotation-enabled.
    expect(rotated.length).toBeGreaterThanOrEqual(2);
  });

  it('encrypts the DLQ with a customer-managed CMK (not the AWS-managed alias)', () => {
    template.hasResourceProperties('AWS::SQS::Queue', {
      KmsMasterKeyId: Match.objectLike({ 'Fn::GetAtt': Match.anyValue() }),
    });
    expect(
      Object.keys(template.findResources('AWS::SQS::Queue')).length,
    ).toBeGreaterThan(0);
  });

  it('does not attach the AWS-managed AWSLambdaBasicExecutionRole', () => {
    const roles = template.findResources('AWS::IAM::Role');
    expect(JSON.stringify(roles)).not.toContain('AWSLambdaBasicExecutionRole');
  });

  it('stamps the provenance Description marker only this construct sets (#175)', () => {
    // The integration adapter (iac/cdk/deploy.ts) reads this marker back via
    // GetFunction after deploy and FAILS LOUDLY if it is absent, so a stale or
    // foreign function of the same name can never let the integration tier
    // green without exercising a freshly-provisioned DoublerFunction. Lock the
    // marker into the synthesized template so the read-back has something to
    // assert against and a future edit that drops it fails here.
    template.hasResourceProperties('AWS::Lambda::Function', {
      Description: DOUBLER_PROVENANCE_DESCRIPTION,
    });
  });

  it('stamps the provenance CDK tag on the function (#175)', () => {
    template.hasResourceProperties('AWS::Lambda::Function', {
      Tags: Match.arrayWith([
        Match.objectLike({
          Key: DOUBLER_PROVENANCE_TAG.key,
          Value: DOUBLER_PROVENANCE_TAG.value,
        }),
      ]),
    });
  });

  it('honors an explicit functionName prop', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'NamedStack');
    new DoublerFunction(stack, 'Named', { functionName: 'my-doubler' });
    const named = Template.fromStack(stack);
    named.hasResourceProperties('AWS::Lambda::Function', {
      FunctionName: 'my-doubler',
    });
    expect(
      Object.keys(named.findResources('AWS::Lambda::Function')).length,
    ).toBeGreaterThan(0);
  });

  it('exposes the underlying lambda.Function so callers can wire it up', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'HandleStack');
    const doubler = new DoublerFunction(stack, 'Handle');
    // The public `fn` handle is a real Lambda function construct.
    expect(doubler.fn.functionArn).toBeDefined();
  });
});
