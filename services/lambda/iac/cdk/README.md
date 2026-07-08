# Lambda — CDK provisioner

The CDK slice of the Lambda vertical (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
sub-issue B / [#136](https://github.com/scottschreckengaust/e2e-ministack/issues/136);
self-provisioning [#147](https://github.com/scottschreckengaust/e2e-ministack/issues/147)).

This vertical **owns and self-provisions its own CDK app + stack** — it is fully
decoupled from the demo stack `lib/ministack-stack.ts` (the "compat = proof" half
of the sample-vs-proof split). See
[`services/README.md`](../../../README.md#per-vertical-self-provisioning-147).

## Files

- **`construct.ts`** — `DoublerFunction`, a standalone reusable construct that
  mirrors the hardened `cdk-doubler` defined inline in
  [`lib/ministack-stack.ts`](../../../../lib/ministack-stack.ts): Node 24
  runtime, the repo-root `lambda/` asset + `index.handler`, a least-privilege
  customer-managed role, a KMS-encrypted log group on a rotated CMK, a
  dead-letter queue on its own rotated CMK, and reserved concurrency — so it
  passes cdk-nag (AwsSolutions) and checkov identically. Takes an optional
  `functionName` prop (defaults to `cdk-doubler`) and exposes the underlying
  `lambda.Function` as `fn`. It is under `iac/**` but is **not** named
  `deploy.ts`, so it is **coverage-gated at 100%** and fully exercised by the
  pure-synth unit test
  [`test/unit/services/lambda-construct.test.ts`](../../../../test/unit/services/lambda-construct.test.ts).

- **`stack.ts`** — `CompatLambdaStack`, this vertical's own `cdk.Stack`. It
  instantiates `DoublerFunction` under the **distinct** physical name
  `compat-lambda-doubler` (exported as `COMPAT_LAMBDA_FUNCTION_NAME`) so it never
  collides with the demo `cdk-doubler` in MiniStack's single global namespace.
  The caller passes `env: MINISTACK_ENV` so the account/region are pinned
  unconditionally (the issue-#2 defense). **100%-gated** — held by
  [`test/unit/services/lambda-compat-stack.test.ts`](../../../../test/unit/services/lambda-compat-stack.test.ts).

- **`app.ts`** — the per-vertical CDK app entrypoint (Decision #2:
  `services/<svc>/iac/<tool>/` owns its own app; this is NOT wired into
  `bin/app.ts`). `buildCompatApp()` news up `CompatLambdaStack` and attaches
  cdk-nag via the v3 API `Validations.of(app).addPlugins(new
AwsSolutionsChecks(...))`, then runs at module top level so
  `cdk deploy CompatLambdaStack --app "npx ts-node --prefer-ts-exts
  services/lambda/iac/cdk/app.ts"` works. Also **100%-gated**.

- **`deploy.ts`** — `cdkLambda: DeployAdapter<LambdaContract>`. `deploy()` is
  **verify-or-provision** against `CompatLambdaStack`:
  1. **Verify** (fast path): `GetFunction` for `compat-lambda-doubler` at the
     MiniStack endpoint. If present, return `{ functionName:
'compat-lambda-doubler' }` without redeploying — so idempotent re-runs
     never double-deploy.
  2. **Provision** (absent → `ResourceNotFoundException`): run `cdk bootstrap`
     (idempotent) then `cdk deploy CompatLambdaStack --require-approval never`
     via the compat app, using `execFile` with an argv **array** (no shell), then
     return the contract.

  The `cdk` calls run with `cwd` = repo root and `--app` pointing at the
  absolute `app.ts` path so they resolve regardless of the launch directory. The
  execFile `env` **backfills `AWS_ENDPOINT_URL_S3`** (defaulting to
  `AWS_ENDPOINT_URL`): the CI Integration job's test step deliberately omits it
  (only the demo-stack deploy steps set it), but `cdk bootstrap`/`cdk deploy`
  running inside that step both need it for asset/staging-bucket upload
  (S3 virtual-host addressing can't be inferred from the generic endpoint).
  No `teardown`: cross-vertical reset uses `POST /_ministack/reset` (the upstream
  pattern) and the adapter must never tear down the demo stack; leaving the
  compat stack up also lets the verify fast-path short-circuit later runs. It
  runs only in the integration tier → **coverage-EXCLUDED** (the
  `iac/**/deploy.ts` path convention).

## Adding another IaC tool

Copy this directory's shape under `iac/<tool>/`, implement a
`DeployAdapter<LambdaContract>` in its `deploy.ts` that owns and self-provisions
that tool's own artifact(s) (any topology), and add that adapter as one entry to
the `adapters` array in `test/integration/services/lambda.test.ts`. The oracles
(`checks.sdk.ts` / `checks.cli.ts`) do not change.
