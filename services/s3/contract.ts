import type { Contract } from '../_harness/adapter';

/**
 * The typed handle the S3 vertical's oracles consume (epic #117, #139). It
 * narrows the harness's open {@link Contract} marker to the minimal shape both
 * the SDK and CLI oracles need: the physical name of the deployed bucket. It
 * carries no IaC-tool identity, which is what lets one `checkSdk`/`checkCli`
 * pair run unchanged against a bucket provisioned by CDK, Terraform, or
 * CloudFormation.
 *
 * Mirrors {@link ../lambda/contract.LambdaContract} — the second vertical of the
 * series (S3 here, DynamoDB in #140).
 *
 * Types-only: erases to zero runtime statements, so it contributes nothing to
 * the unit-tier coverage gate.
 */
export interface S3Contract extends Contract {
  /** Physical name of the deployed data bucket, e.g. `compat-s3-bucket`. */
  bucketName: string;
}
