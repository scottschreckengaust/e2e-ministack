#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MiniStackStack } from '../lib/ministack-stack';

const app = new cdk.App();

new MiniStackStack(app, 'MiniStackTestStack', {
  // Pin a deterministic account/region so the same bootstrap environment
  // (aws://000000000000/us-east-1) is used locally and in CI against MiniStack.
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT ?? '000000000000',
    region: process.env.CDK_DEFAULT_REGION ?? 'us-east-1',
  },
});

// cdk-nag v3 registers rule packs via CDK's policy-validation framework
// (NOT the v2 `Aspects.of(app).add(...)` API). Checks run at synth time and
// any unsuppressed finding fails synth. verbose surfaces rule explanations.
Validations.of(app).addPlugins(new AwsSolutionsChecks(app, { verbose: true }));
