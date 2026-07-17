# DynamoDB — Terraform provisioner (RESERVED)

**RESERVED — not yet implemented.** This directory is a placeholder for the
Terraform slice of the DynamoDB vertical, tracked as a future sub-issue of epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117).

When implemented it will hold a `main.tf` (an `aws_dynamodb_table` provisioning a
hardened table-equivalent against MiniStack via the Terraform AWS provider's
custom-endpoints block) and a `deploy.ts` exporting a
`DeployAdapter<DynamoContract>` whose `deploy()` runs `terraform init`/`apply`
and `teardown()` runs `terraform destroy`.

The behavioral oracles are **already defined once** in
[`services/dynamodb/checks.sdk.ts`](../../checks.sdk.ts) and
[`services/dynamodb/checks.cli.ts`](../../checks.cli.ts) — they are
provisioner-blind, so this vertical reuses them unchanged. Wiring is one extra
entry in the `adapters` array of
[`test/integration/services/dynamodb.test.ts`](../../../../test/integration/services/dynamodb.test.ts),
plus a `dynamodb × AWS::DynamoDB::Table × terraform` row appended to
[`provisioning.json`](../../../_registry/provisioning.json).

That a resource can be green under one tool and red under another (CloudFormation
resource-type coverage lags raw API coverage) is exactly the finding this axis
is designed to record — see [`services/README.md`](../../../README.md).
