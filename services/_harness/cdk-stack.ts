import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { MINISTACK_ENV } from '../../lib/env';

/**
 * Abstract base for every CDK compat vertical's stack (epic #117, #147).
 *
 * It pins the deploy target to MINISTACK_ENV UNCONDITIONALLY — the issue-#2
 * defense: the CDK CLI otherwise populates CDK_DEFAULT_ACCOUNT/REGION from the
 * ambient credential chain, so a contributor with live AWS creds could deploy a
 * compat stack against their real account. `props` is narrowed to
 * `Omit<cdk.StackProps,'env'>` so a caller CANNOT pass (or mis-set) `env` — the
 * pin is unrepresentable-if-wrong at compile time, not merely documented — while
 * still forwarding every other StackProp (tags, description, …).
 *
 * Each vertical extends this (CompatLambdaStack; #139 CompatS3Stack, #140
 * CompatDynamoStack) so the pin lives in ONE tested place rather than being
 * re-typed per stack. Abstract so it is never instantiated directly.
 */
export abstract class CompatStack extends cdk.Stack {
  constructor(
    scope: Construct,
    id: string,
    props?: Omit<cdk.StackProps, 'env'>,
  ) {
    super(scope, id, { ...props, env: MINISTACK_ENV });
  }
}
