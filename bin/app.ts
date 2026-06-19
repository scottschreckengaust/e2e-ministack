#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MiniStackStack } from '../lib/ministack-stack';
import { MINISTACK_ENV } from '../lib/env';

export function buildApp(): cdk.App {
  const app = new cdk.App();

  // Pin the deploy target to MiniStack's fixed account/region unconditionally.
  // Do NOT read CDK_DEFAULT_ACCOUNT/REGION here: the CDK CLI sets those from
  // the ambient credential chain (AWS_PROFILE / SSO / IMDS), so a contributor
  // with live AWS creds would otherwise synth/deploy against their real
  // account. See lib/env.ts and issue #2.
  new MiniStackStack(app, 'MiniStackTestStack', {
    env: MINISTACK_ENV,
  });

  // cdk-nag v3 registers rule packs via CDK's policy-validation framework
  // (NOT the v2 `Aspects.of(app).add(...)` API). Checks run at synth time and
  // any unsuppressed finding fails synth. verbose surfaces rule explanations.
  Validations.of(app).addPlugins(
    new AwsSolutionsChecks(app, { verbose: true }),
  );

  return app;
}

buildApp();
