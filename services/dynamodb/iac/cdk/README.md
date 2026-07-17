# DynamoDB — CDK provisioner

The CDK slice of the DynamoDB vertical (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
[#140](https://github.com/scottschreckengaust/e2e-ministack/issues/140);
self-provisioning [#147](https://github.com/scottschreckengaust/e2e-ministack/issues/147)).

This vertical **owns and self-provisions its own CDK app + stack** — it is fully
decoupled from the demo stack `lib/ministack-stack.ts` (the "compat = proof" half
of the sample-vs-proof split). It is a structural clone of the
[Lambda CDK provisioner](../../../lambda/iac/cdk/README.md) and the
[S3 CDK provisioner](../../../s3/iac/cdk/README.md), but it **authors a fresh
hardened resource** rather than mirroring one already in `lib/`.

## Files

- **`construct.ts`** — `HardenedTable`, a standalone reusable construct that
  authors a hardened `dynamodb.Table`:
  - **Point-in-time recovery enabled** (cdk-nag AwsSolutions-DDB3).
  - **Customer-managed KMS encryption** on a rotated CMK (defense-in-depth beyond
    the AWS-owned default; checkov CKV_AWS_119).
  - **PAY_PER_REQUEST** billing (no provisioned capacity to autoscale).
  - **`DESTROY`** removal policy (MiniStack is ephemeral; no
    autoDeleteObjects-style custom resource that stalls the emulator).

  The partition key is the distinctive `COMPAT_DYNAMO_PARTITION_KEY`, which
  doubles as the vertical's **primary provenance marker** (read back by
  `deploy.ts`); a secondary CDK tag (`COMPAT_DYNAMO_PROVENANCE_TAG`) is applied
  belt-and-braces. Takes an optional `tableName` prop (defaults to
  `cdk-demo-table`) and exposes the underlying `dynamodb.Table` as `table`. Under
  `iac/**` but not named `deploy.ts`, so it is **coverage-gated at 100%** and
  fully exercised by the pure-synth unit test
  [`test/unit/services/dynamodb-construct.test.ts`](../../../../test/unit/services/dynamodb-construct.test.ts).

- **`stack.ts`** — `CompatDynamoStack`, this vertical's own `cdk.Stack`. It
  instantiates `HardenedTable` under the **distinct** physical name
  `compat-dynamo-table` (exported as `COMPAT_DYNAMO_TABLE_NAME`) so it never
  collides in MiniStack's single global namespace. Extends the `CompatStack`
  base, which pins the account/region to `MINISTACK_ENV` unconditionally (the
  issue-#2 defense). **100%-gated** — held by
  [`test/unit/services/dynamodb-compat-stack.test.ts`](../../../../test/unit/services/dynamodb-compat-stack.test.ts).

- **`app.ts`** — the per-vertical CDK app entrypoint (Decision #2:
  `services/<svc>/iac/<tool>/` owns its own app; this is NOT wired into
  `bin/app.ts`). `buildCompatApp()` news up `CompatDynamoStack` and attaches
  cdk-nag via the v3 API
  `Validations.of(app).addPlugins(new AwsSolutionsChecks(...))`, then runs at
  module top level so `cdk deploy CompatDynamoStack --app "npx ts-node
--prefer-ts-exts services/dynamodb/iac/cdk/app.ts"` works. Also **100%-gated**.

- **`deploy.ts`** — `cdkDynamo: DeployAdapter<DynamoContract>`. `deploy()` is
  **verify-or-provision** against `CompatDynamoStack`:
  1. **Verify** (fast path): `DescribeTable` for `compat-dynamo-table` at the
     MiniStack endpoint. If present, healthy, AND carrying the provenance marker,
     return `{ tableName: 'compat-dynamo-table' }` without redeploying.
  2. **Provision** (absent → `ResourceNotFoundException`): run `cdk bootstrap`
     (idempotent) then `cdk deploy CompatDynamoStack --require-approval never` via
     the compat app, using `execFile` with an argv **array** (no shell).
  3. **Prove provenance** (mirrors #175): on BOTH paths, `DescribeTable` once more
     and assert the table's HASH key is `COMPAT_DYNAMO_PARTITION_KEY`. A stale or
     foreign table of the same name lacks it → throw loudly rather than green
     against a resource this stack never provisioned.

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
`DeployAdapter<DynamoContract>` in its `deploy.ts` that owns and self-provisions
that tool's own artifact(s) (any topology), and add that adapter as one entry to
the `adapters` array in `test/integration/services/dynamodb.test.ts`. The oracles
(`checks.sdk.ts` / `checks.cli.ts`) do not change.
