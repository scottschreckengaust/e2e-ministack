import type { Contract } from '../_harness/adapter';

/**
 * The typed handle the DynamoDB vertical's oracles consume (epic #117, #140). It
 * narrows the harness's open {@link Contract} marker to the minimal shape both
 * the SDK and CLI oracles need: the physical name of the deployed table. It
 * carries no IaC-tool identity, which is what lets one `checkSdk`/`checkCli`
 * pair run unchanged against a table provisioned by CDK, Terraform, or
 * CloudFormation.
 *
 * Mirrors {@link ../lambda/contract.LambdaContract} and
 * {@link ../s3/contract.S3Contract} — the third vertical of the series (Lambda
 * first, S3 in #139, DynamoDB here).
 *
 * Types-only: erases to zero runtime statements, so it contributes nothing to
 * the unit-tier coverage gate.
 */
export interface DynamoContract extends Contract {
  /** Physical name of the deployed table, e.g. `compat-dynamo-table`. */
  tableName: string;
}
