# DynamoDB — CloudFormation provisioner (RESERVED)

**RESERVED — not yet implemented.** This directory is a placeholder for the
raw-CloudFormation slice of the DynamoDB vertical, tracked as a future sub-issue
of epic [#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117).

When implemented it will hold a `template.yaml` (an `AWS::DynamoDB::Table`
provisioning a hardened table-equivalent) and a `deploy.ts` exporting a
`DeployAdapter<DynamoContract>` whose `deploy()` calls `aws cloudformation
deploy` / `create-stack` against MiniStack and `teardown()` calls `delete-stack`.

The behavioral oracles are **already defined once** in
[`services/dynamodb/checks.sdk.ts`](../../checks.sdk.ts) and
[`services/dynamodb/checks.cli.ts`](../../checks.cli.ts) — they are
provisioner-blind, so this vertical reuses them unchanged. Wiring is one extra
entry in the `adapters` array of
[`test/integration/services/dynamodb.test.ts`](../../../../test/integration/services/dynamodb.test.ts),
plus a `dynamodb × AWS::DynamoDB::Table × cloudformation` row appended to
[`provisioning.json`](../../../_registry/provisioning.json).

Comparing the CDK, Terraform, and raw-CloudFormation rows for the same
`(service × resource)` is the point: it isolates whether a red result is a
MiniStack API gap or an IaC-tool coverage gap — see
[`services/README.md`](../../../README.md).
