import * as cdk from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { DoublerFunction } from './construct';

/**
 * Physical function name for the compat vertical's self-provisioned Lambda.
 *
 * DELIBERATELY DISTINCT from the demo stack's `cdk-doubler`
 * (lib/ministack-stack.ts): MiniStack shares one global namespace, so a compat
 * stack that reused `cdk-doubler` would collide with the demo stack whenever
 * both are deployed (as in CI, where `cdk deploy` of the demo stack precedes
 * the integration tier). A distinct name makes the harness independent of
 * whether the demo stack is deployed at all — this is the #147 decoupling.
 */
export const COMPAT_LAMBDA_FUNCTION_NAME = 'compat-lambda-doubler';

/**
 * The Lambda/CDK vertical's own self-provisioned compat stack (epic #117,
 * #147). It instantiates the reusable {@link DoublerFunction} construct under a
 * distinct physical name so the compat harness can `cdk deploy` this stack
 * INDEPENDENTLY of the demo stack `lib/ministack-stack.ts`.
 *
 * This is the "compat = proof" half of the sample-vs-proof split: `lib/` stays
 * a decoupled demo (with its own `test/integration/integration.test.ts`), while
 * each compat vertical owns and provisions its own `Compat*Stack`. The CDK
 * adapter (iac/cdk/deploy.ts) verify-or-provisions THIS stack; the returned
 * {@link LambdaContract} names {@link COMPAT_LAMBDA_FUNCTION_NAME}.
 *
 * Reuses `MINISTACK_ENV` (via the caller passing `env`) so the account/region
 * are pinned unconditionally — the issue-#2 defense — keeping the deploy target
 * independent of the ambient `CDK_DEFAULT_*` the CDK CLI would otherwise inject.
 */
export class CompatLambdaStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    new DoublerFunction(this, 'Doubler', {
      functionName: COMPAT_LAMBDA_FUNCTION_NAME,
    });
  }
}
