# S3 vertical (`services/s3/`)

The second service vertical of the MiniStack compatibility harness (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
[#139](https://github.com/scottschreckengaust/e2e-ministack/issues/139)). It
proves the harness on **S3 × CDK** with **both** oracles, a structural clone of
the pilot [Lambda vertical](../lambda/README.md) (DynamoDB follows in
[#140](https://github.com/scottschreckengaust/e2e-ministack/issues/140)).

## Layout

```text
services/s3/
  README.md          # this file
  contract.ts        # S3Contract = Contract & { bucketName: string } (types-only)
  health.ts          # isBucketHeadHealthy — HeadBucket health predicate (100%-gated)
  checks.sdk.ts      # checkSdk — typed AWS SDK v3 oracle   (defined ONCE, integration tier)
  checks.cli.ts      # checkCli — documented AWS CLI oracle  (defined ONCE, integration tier)
  iac/
    cdk/
      construct.ts   # HardenedBucket — reusable data+log bucket construct (100%-gated)
      stack.ts       # CompatS3Stack — self-provisioned compat stack (100%-gated)
      app.ts         # buildCompatApp — per-vertical CDK app entrypoint (100%-gated)
      deploy.ts      # cdkS3: DeployAdapter<S3Contract> (verify-or-provision, integration tier)
      README.md
    terraform/       # RESERVED — README stub only (future sub-issue)
    cloudformation/  # RESERVED — README stub only (future sub-issue)
```

The behavioral matrix lives in
[`test/integration/services/s3.test.ts`](../../test/integration/services/s3.test.ts):
`describe.each(adapters) × it.each(oracles)`. With `adapters = [cdkS3]` and
`oracles = { sdk, cli }` it emits the named JUnit cases
`s3 provisioned via cdk › passes the sdk oracle` and `… passes the cli oracle`
to `reports/junit/integration.xml`.

## The two oracles (provisioner-blind, defined once)

Both take only an `S3Contract` (the bucket name) and never know which IaC tool
created the bucket — that indirection is what lets one oracle pair be shared
across CDK, Terraform, and CloudFormation. Each does a full object **round-trip**
against the deployed bucket (parity with the S3 round-trip in the demo
`test/integration/integration.test.ts`):

- **`checkSdk`** — via `@aws-sdk/client-s3`: `PutObject` a unique key, `GetObject`
  it back, assert the body round-trips byte-for-byte, then `DeleteObject` in a
  `finally` (idempotent against a reused emulator, issue #10). `forcePathStyle`
  is required against MiniStack's single-host endpoint.
- **`checkCli`** — the EXACT commands a human pastes into AWS CloudShell:
  `aws s3api put-object --bucket <name> --key <k> --body <file>` then
  `aws s3api get-object --bucket <name> --key <k> <outfile>`, then compare the
  downloaded body. The object is deleted afterward. Args are passed to `execFile`
  as an argv array (never a shell string) — no shell, no injection surface; the
  request/response bodies use per-invocation temp files that are read/written +
  unlinked.

### `ministackEnv` helper

`checks.cli.ts` exports `ministackEnv`: the environment the AWS CLI needs to
reach MiniStack — `AWS_ENDPOINT_URL` (default `http://localhost:4566`),
`AWS_REGION`/`AWS_DEFAULT_REGION` (`us-east-1`), and the dummy `test`/`test`
credentials — from the shared `_harness/aws-env` module (each default applied
only when the var is absent).

## The CDK vertical (self-provisioning — #147)

This vertical **owns and self-provisions its own CDK app + stack**, fully
decoupled from the demo stack `lib/ministack-stack.ts` (the "compat = proof" half
of the sample-vs-proof split). File-level detail is in
[`iac/cdk/README.md`](iac/cdk/README.md); in brief:

- **`iac/cdk/construct.ts`** — `HardenedBucket`, a standalone reusable construct
  mirroring the `cdk-demo-bucket` + `cdk-demo-log-bucket` pair in
  [`lib/ministack-stack.ts`](../../lib/ministack-stack.ts): a data bucket that
  ships access logs to a dedicated log bucket which logs to itself, both with
  TLS enforced, SSE, block-all-public, versioning, and bounded lifecycle rules —
  so it passes cdk-nag (AwsSolutions-S1/S2/S10) and checkov (CKV_AWS_18/21/300)
  identically. **100%-gated**, exercised by
  [`test/unit/services/s3-construct.test.ts`](../../test/unit/services/s3-construct.test.ts).
- **`iac/cdk/stack.ts`** — `CompatS3Stack`, this vertical's own `cdk.Stack`,
  instantiating `HardenedBucket` under the **distinct** physical name
  `compat-s3-bucket` so it never collides with the demo `cdk-demo-bucket` in
  MiniStack's single global namespace. Pinned to `MINISTACK_ENV`. **100%-gated**.
- **`iac/cdk/app.ts`** — `buildCompatApp()`, the per-vertical CDK app entrypoint
  (owned by the vertical, NOT `bin/app.ts`); attaches cdk-nag via the v3
  `Validations.of(app).addPlugins(...)` API. **100%-gated**.
- **`iac/cdk/deploy.ts`** — `cdkS3: DeployAdapter<S3Contract>`. `deploy()` is
  **verify-or-provision**: `HeadBucket` for `compat-s3-bucket` (fast path, no
  redeploy); on `NotFound`/`NoSuchBucket` it runs `cdk bootstrap` + `cdk deploy
CompatS3Stack` via the compat app. No `teardown`.

## Coverage

Per the merged `jest.config.js` path-convention excludes (no per-vertical config
edits needed):

- `checks.sdk.ts`, `checks.cli.ts` (`checks.*.ts`) and `iac/cdk/deploy.ts`
  (`iac/**/deploy.ts`) run only in the **integration tier** against a live
  MiniStack, so istanbul can't instrument them — **coverage-EXCLUDED**.
- `contract.ts` is types-only → erases to zero runtime statements.
- `health.ts`, `iac/cdk/construct.ts`, `iac/cdk/stack.ts`, and `iac/cdk/app.ts`
  are pure logic/synth → **100%-gated**, held there by
  `s3-health.test.ts`, `s3-construct.test.ts`, and `s3-compat-stack.test.ts`.

The integration matrix's correctness is verified by CI's **Integration
(MiniStack)** job on the PR (it cannot run locally without an emulator).

## MiniStack S3 boundary notes

- MiniStack serves S3 on the single local endpoint (port 4566), so every SDK/CLI
  client uses `forcePathStyle` / the generic `AWS_ENDPOINT_URL` — virtual-host
  bucket addressing can't resolve against one host. This is the same round-trip
  the demo `cdk-demo-bucket` already proves.
- Axis-1 breadth for S3 is recorded as `supported` in
  [`services/_registry/ministack-support.json`](../_registry/ministack-support.json);
  this vertical adds the Axis-2 `s3 × AWS::S3::Bucket × cdk` row to
  [`provisioning.json`](../_registry/provisioning.json).

## Upstream references

- MiniStack supported services (S3): <https://github.com/ministackorg/ministack#supported-services>
- AWS CLI `s3api put-object` / `get-object`: <https://docs.aws.amazon.com/cli/latest/reference/s3api/>
- `@aws-sdk/client-s3` `PutObjectCommand` / `GetObjectCommand`: <https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/s3/>
