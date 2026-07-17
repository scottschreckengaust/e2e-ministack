# S3 — CloudFormation provisioner (RESERVED)

**RESERVED — not yet implemented.** This directory is a placeholder for the
raw-CloudFormation slice of the S3 vertical, tracked as a future sub-issue of
epic [#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117).

When implemented it will hold a `template.yaml` (an `AWS::S3::Bucket`
provisioning a hardened data-bucket-equivalent) and a `deploy.ts` exporting a
`DeployAdapter<S3Contract>` whose `deploy()` calls `aws cloudformation deploy` /
`create-stack` against MiniStack and `teardown()` calls `delete-stack`.

The behavioral oracles are **already defined once** in
[`services/s3/checks.sdk.ts`](../../checks.sdk.ts) and
[`services/s3/checks.cli.ts`](../../checks.cli.ts) — they are provisioner-blind,
so this vertical reuses them unchanged. Wiring is one extra entry in the
`adapters` array of
[`test/integration/services/s3.test.ts`](../../../../test/integration/services/s3.test.ts),
plus an `s3 × AWS::S3::Bucket × cloudformation` row appended to
[`provisioning.json`](../../../_registry/provisioning.json).

Comparing the CDK, Terraform, and raw-CloudFormation rows for the same
`(service × resource)` is the point: it isolates whether a red result is a
MiniStack API gap or an IaC-tool coverage gap — see
[`services/README.md`](../../../README.md).
