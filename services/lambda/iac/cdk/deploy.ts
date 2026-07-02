import type { DeployAdapter } from '../../../_harness/adapter';
import type { LambdaContract } from '../../contract';

/**
 * The CDK {@link DeployAdapter} for the Lambda vertical (epic #117,
 * sub-issue B / #136).
 *
 * It SHORT-CIRCUITS: CI runs `cdk deploy` (which provisions `cdk-doubler` from
 * lib/ministack-stack.ts) BEFORE the integration tier, so `deploy()` returns
 * the contract for that already-deployed function without redeploying. This is
 * exactly the short-circuit the harness's `DeployAdapter` contract sanctions
 * for CDK (other IaC tools — Terraform, CloudFormation — will do the real
 * apply/deploy inside their own `deploy()`). No `teardown`: the function is a
 * shared, pre-deployed resource owned by the main stack, not by this adapter.
 *
 * Adapter (matches the coverage-excluded `iac deploy.ts` path convention in
 * jest.config.js): integration-tier only, so it collects no unit coverage.
 */
export const cdkLambda: DeployAdapter<LambdaContract> = {
  name: 'cdk',
  async deploy(): Promise<LambdaContract> {
    return { functionName: 'cdk-doubler' };
  },
};
