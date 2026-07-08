#!/usr/bin/env node
import * as cdk from 'aws-cdk-lib';
import { Validations } from 'aws-cdk-lib';
import { AwsSolutionsChecks } from 'cdk-nag';
import { CompatLambdaStack } from './stack';

/**
 * The per-vertical CDK app entrypoint for the Lambda/CDK compat vertical (epic
 * #117, #147).
 *
 * DECISION #2 (locked on the thread): each `services/<svc>/iac/<tool>/` owns its
 * OWN app(s)/stack(s) — this is NOT wired into the repo-root `bin/app.ts` (which
 * stays the demo stack's entrypoint). The topology is agnostic: a vertical may
 * ship a single stack, multiple stacks, nested stacks, or cross-app-via-outputs;
 * `DeployAdapter.deploy()` provisions whatever shape it owns and returns the
 * `Contract`. Here the Lambda vertical ships one stack.
 *
 * Mirrors `bin/app.ts`: the deploy target is pinned to `MINISTACK_ENV` (issue
 * #2 — do NOT read `CDK_DEFAULT_*`, which the CDK CLI populates from the ambient
 * credential chain) by the {@link CompatStack} base the stack extends, so this
 * entrypoint no longer passes `env` itself. It attaches cdk-nag through the v3
 * policy-validation API
 * (`Validations.of(app).addPlugins(...)`, NOT the v2 `Aspects` API) so any
 * unsuppressed AwsSolutions finding fails synth. `verbose` surfaces rule text.
 *
 * The adapter (iac/cdk/deploy.ts) deploys this via:
 *   cdk deploy CompatLambdaStack --require-approval never \
 *     --app "npx ts-node --prefer-ts-exts services/lambda/iac/cdk/app.ts"
 * so the module MUST call `buildCompatApp()` at top level (below).
 */
export function buildCompatApp(): cdk.App {
  const app = new cdk.App();

  new CompatLambdaStack(app, 'CompatLambdaStack');

  Validations.of(app).addPlugins(
    new AwsSolutionsChecks(app, { verbose: true }),
  );

  return app;
}

buildCompatApp();
