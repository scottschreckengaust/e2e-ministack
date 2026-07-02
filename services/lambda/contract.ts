import type { Contract } from '../_harness/adapter';

/**
 * The typed handle the Lambda vertical's oracles consume (epic #117,
 * sub-issue B / #136). It narrows the harness's open {@link Contract} marker
 * to the minimal shape both the SDK and CLI oracles need: the physical
 * function name to invoke. It carries no IaC-tool identity, which is what lets
 * one `checkSdk`/`checkCli` pair run unchanged against a Lambda provisioned by
 * CDK, Terraform, or CloudFormation.
 *
 * Types-only: erases to zero runtime statements, so it contributes nothing to
 * the unit-tier coverage gate.
 */
export interface LambdaContract extends Contract {
  /** Physical name of the deployed function, e.g. `cdk-doubler`. */
  functionName: string;
}
