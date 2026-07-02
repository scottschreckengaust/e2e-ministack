# Lambda — CDK provisioner

The CDK slice of the Lambda vertical (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
sub-issue B / [#136](https://github.com/scottschreckengaust/e2e-ministack/issues/136)).

## Files

- **`construct.ts`** — `DoublerFunction`, a standalone reusable construct that
  mirrors the hardened `cdk-doubler` defined inline in
  [`lib/ministack-stack.ts`](../../../../lib/ministack-stack.ts): Node 24
  runtime, the repo-root `lambda/` asset + `index.handler`, a least-privilege
  customer-managed role, a KMS-encrypted log group on a rotated CMK, a
  dead-letter queue on its own rotated CMK, and reserved concurrency — so it
  passes cdk-nag (AwsSolutions) and checkov identically. Takes an optional
  `functionName` prop (defaults to `cdk-doubler`) and exposes the underlying
  `lambda.Function` as `fn`.

  **Additive by design.** This construct is NOT wired into the deployed
  `MiniStackStack`; the adapter below short-circuits to the already-deployed
  `cdk-doubler`. Keeping it standalone keeps #136 off `lib/`, the CDK snapshot,
  and the cdk-nag/checkov re-verification a live-stack refactor would trigger.
  It documents and proves the hardened doubler-equivalent construct the harness
  exposes for reuse. It is under `iac/**` but is **not** named `deploy.ts`, so
  it is **coverage-gated at 100%** and fully exercised by the pure-synth unit
  test
  [`test/unit/services/lambda-construct.test.ts`](../../../../test/unit/services/lambda-construct.test.ts).

- **`deploy.ts`** — `cdkLambda: DeployAdapter<LambdaContract>`. `deploy()`
  **short-circuits** to `{ functionName: 'cdk-doubler' }` because CI runs
  `cdk deploy` before the integration tier — no redeploy. No `teardown`: the
  function is a shared, pre-deployed resource owned by the main stack. This is
  the CDK short-circuit sanctioned by the harness's `DeployAdapter` contract;
  Terraform/CloudFormation adapters will do the real apply/deploy inside their
  own `deploy()`. It runs only in the integration tier → coverage-EXCLUDED.

## Adding another IaC tool

Copy this directory's shape under `iac/<tool>/`, implement a
`DeployAdapter<LambdaContract>` in its `deploy.ts` that does the real
provisioning, and add that adapter as one entry to the `adapters` array in
`test/integration/services/lambda.test.ts`. The oracles (`checks.sdk.ts` /
`checks.cli.ts`) do not change.
