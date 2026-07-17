# S3 — CDK provisioner

The CDK slice of the S3 vertical (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
[#139](https://github.com/scottschreckengaust/e2e-ministack/issues/139);
self-provisioning [#147](https://github.com/scottschreckengaust/e2e-ministack/issues/147)).

This vertical **owns and self-provisions its own CDK app + stack** — it is fully
decoupled from the demo stack `lib/ministack-stack.ts` (the "compat = proof" half
of the sample-vs-proof split). See
[`services/README.md`](../../../README.md#per-vertical-self-provisioning-147).
It is a structural clone of the pilot
[Lambda CDK provisioner](../../../lambda/iac/cdk/README.md).

## Files

- **`construct.ts`** — `HardenedBucket`, a standalone reusable construct that
  mirrors the `cdk-demo-bucket` + `cdk-demo-log-bucket` pair defined inline in
  [`lib/ministack-stack.ts`](../../../../lib/ministack-stack.ts): a data bucket
  that ships its S3 server access logs to a dedicated log bucket which logs to
  itself, both with TLS enforced, S3-managed SSE, block-all-public, versioning,
  and bounded lifecycle rules — so it passes cdk-nag (AwsSolutions-S1/S2/S10) and
  checkov (CKV_AWS_18/21/300) identically. Takes an optional `bucketName` prop
  (defaults to `cdk-demo-bucket`; the log bucket is `<bucketName>-logs`) and
  exposes the underlying data `s3.Bucket` as `bucket`. Under `iac/**` but not
  named `deploy.ts`, so it is **coverage-gated at 100%** and fully exercised by
  the pure-synth unit test
  [`test/unit/services/s3-construct.test.ts`](../../../../test/unit/services/s3-construct.test.ts).

- **`stack.ts`** — `CompatS3Stack`, this vertical's own `cdk.Stack`. It
  instantiates `HardenedBucket` under the **distinct** physical name
  `compat-s3-bucket` (exported as `COMPAT_S3_BUCKET_NAME`) so it never collides
  with the demo `cdk-demo-bucket` in MiniStack's single global namespace. Extends
  the `CompatStack` base, which pins the account/region to `MINISTACK_ENV`
  unconditionally (the issue-#2 defense). **100%-gated** — held by
  [`test/unit/services/s3-compat-stack.test.ts`](../../../../test/unit/services/s3-compat-stack.test.ts).

- **`app.ts`** — the per-vertical CDK app entrypoint (Decision #2:
  `services/<svc>/iac/<tool>/` owns its own app; this is NOT wired into
  `bin/app.ts`). `buildCompatApp()` news up `CompatS3Stack` and attaches cdk-nag
  via the v3 API `Validations.of(app).addPlugins(new AwsSolutionsChecks(...))`,
  then runs at module top level so `cdk deploy CompatS3Stack --app "npx ts-node
--prefer-ts-exts services/s3/iac/cdk/app.ts"` works. Also **100%-gated**.

- **`deploy.ts`** — `cdkS3: DeployAdapter<S3Contract>`. `deploy()` is
  **verify-or-provision** against `CompatS3Stack`:
  1. **Verify** (fast path): `HeadBucket` for `compat-s3-bucket` at the MiniStack
     endpoint (`forcePathStyle` for the single-host emulator). If present, return
     `{ bucketName: 'compat-s3-bucket' }` without redeploying.
  2. **Provision** (absent → `NotFound`/`NoSuchBucket`): run `cdk bootstrap`
     (idempotent) then `cdk deploy CompatS3Stack --require-approval never` via
     the compat app, using `execFile` with an argv **array** (no shell), then
     return the contract.

  The `cdk` calls run with `cwd` = repo root and `--app` pointing at the absolute
  `app.ts` path. The execFile `env` **backfills `AWS_ENDPOINT_URL_S3`** (via the
  shared `cdkExecOpts`) so `cdk bootstrap`/`cdk deploy` running inside the CI
  integration test step (which sets `AWS_ENDPOINT_URL` but omits the S3-specific
  var) satisfy the CLI's presence requirement. No `teardown`: cross-vertical
  reset uses `POST /_ministack/reset`; leaving the compat stack up lets the
  verify fast-path short-circuit later runs. Integration tier only →
  **coverage-EXCLUDED** (the `iac/**/deploy.ts` path convention).

## Adding another IaC tool

Copy this directory's shape under `iac/<tool>/`, implement a
`DeployAdapter<S3Contract>` in its `deploy.ts` that owns and self-provisions that
tool's own artifact(s) (any topology), and add that adapter as one entry to the
`adapters` array in `test/integration/services/s3.test.ts`. The oracles
(`checks.sdk.ts` / `checks.cli.ts`) do not change.
