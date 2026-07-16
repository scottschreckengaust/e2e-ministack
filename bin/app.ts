#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { MiniStackStack } from '../lib/ministack-stack';
import { MINISTACK_ENV } from '../lib/env';

export function buildApp(): { app: cdk.App; stack: MiniStackStack } {
  const app = new cdk.App();

  // Pin the deploy target to MiniStack's fixed account/region unconditionally.
  // Do NOT read CDK_DEFAULT_ACCOUNT/REGION here: the CDK CLI sets those from
  // the ambient credential chain (AWS_PROFILE / SSO / IMDS), so a contributor
  // with live AWS creds would otherwise synth/deploy against their real
  // account. See lib/env.ts and issue #2.
  // Capture the construct so its instantiation is a used value (SonarQube
  // S1848): the returned handle lets callers address the stack directly
  // instead of re-finding it via app.node.findChild(...).
  const stack = new MiniStackStack(app, 'MiniStackTestStack', {
    env: MINISTACK_ENV,
  });

  // cdk-nag v3 registers rule packs via CDK's policy-validation framework
  // (NOT the v2 `Aspects.of(app).add(...)` API). Checks run at synth time and
  // any unsuppressed finding fails synth. verbose surfaces rule explanations.
  Validations.of(app).addPlugins(
    new AwsSolutionsChecks(app, { verbose: true }),
  );

  return { app, stack };
}

buildApp();
