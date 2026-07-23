# Lambda vertical (`services/lambda/`)

The first service vertical of the MiniStack compatibility harness (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
sub-issue B / [#136](https://github.com/scottschreckengaust/e2e-ministack/issues/136)).
It proves the harness end-to-end on **one service (Lambda) × one IaC tool
(CDK)** with **both** oracles, and is the reference every later vertical copies.

## Layout

```text
services/lambda/
  README.md          # this file
  contract.ts        # LambdaContract = Contract & { functionName: string } (types-only)
  invoke.ts          # PURE payload-encode / response-parse / CLI-argv seam (100%-gated, #151/#144)
  health.ts          # isFunctionConfigHealthy + hasProvenanceMarker predicates (100%-gated)
  checks.sdk.ts      # checkSdk — typed AWS SDK v3 oracle   (defined ONCE, integration tier)
  checks.cli.ts      # checkCli — documented AWS CLI oracle  (defined ONCE, integration tier)
  iac/
    cdk/
      construct.ts   # DoublerFunction — reusable hardened doubler construct (100%-gated)
      stack.ts       # CompatLambdaStack — self-provisioned compat stack (100%-gated)
      app.ts         # buildCompatApp — per-vertical CDK app entrypoint (100%-gated)
      deploy.ts      # cdkLambda: DeployAdapter<LambdaContract> (verify-or-provision, integration tier)
      README.md
    terraform/       # RESERVED — README stub only (future sub-issue)
    cloudformation/  # RESERVED — README stub only (future sub-issue)
```

The behavioral matrix lives in
[`test/integration/services/lambda.test.ts`](../../test/integration/services/lambda.test.ts):
`describe.each(adapters) × it.each(oracles)`. With `adapters = [cdkLambda]` and
`oracles = { sdk, cli }` it emits the named JUnit cases
`lambda provisioned via cdk › passes the sdk oracle` and
`… passes the cli oracle` to `reports/junit/integration.xml` — no new reporting
plumbing (the integration tier already emits JUnit and collects no coverage).

## The two oracles (provisioner-blind, defined once)

Both take only a `LambdaContract` (the function name) and never know which IaC
tool created the function — that indirection is what lets one oracle pair be
shared across CDK, Terraform, and CloudFormation. Each asserts **parity with
the existing `test/integration/integration.test.ts`** on both paths:

- **`checkSdk`** — invokes via `@aws-sdk/client-lambda`. Happy path `{ n: 21 }`
  → `doubled === 42`, `statusCode === 200`, `nodeVersion` matches `/^v24\./`, no
  `FunctionError`, HTTP `StatusCode` 200. Handled path `{ n: 'abc' }` → payload
  `statusCode === 400`, no `FunctionError` (the handler validates and _returns_
  a 400 envelope; it never throws, so the invoke succeeds at the HTTP layer).
- **`checkCli`** — the EXACT command a human pastes into AWS CloudShell:
  `aws lambda invoke --function-name <name> --payload '{"n":21}'
--cli-binary-format raw-in-base64-out <outfile>`, then parse the response and
  assert `doubled === 42` / `nodeVersion`. Same handled-400 assertion on
  `{ n: 'abc' }`. **The `--payload` is RAW JSON, not base64:** AWS CLI v2 treats
  `--payload` as base64 by default, and `--cli-binary-format raw-in-base64-out`
  flips blob input back to raw — the two must be consistent, or the CLI
  double-handles the value (a base64 string under `raw-in-base64-out` is
  forwarded verbatim, the handler parses the base64 text, and `n` comes back
  NaN ⇒ a bogus 400). Raw JSON is also what a human actually pastes. The
  response body is written to a per-invocation temp file (`os.tmpdir()`, unique
  name) that is read + parsed + unlinked. Args are passed to `execFile` as an
  argv array (never a shell string) — no shell, no injection surface.

### `ministackEnv` helper

`checks.cli.ts` exports `ministackEnv`: the environment the AWS CLI needs to
reach MiniStack — `AWS_ENDPOINT_URL` (default `http://localhost:4566`),
`AWS_REGION`/`AWS_DEFAULT_REGION` (`us-east-1`), and the dummy `test`/`test`
credentials. It copies `process.env` and applies each default only when the var
is absent (never overriding an explicit value). In CI these are all set at the
integration-job level and inherited, so the helper is effectively
`{ ...process.env }`; the point is that the documented command is
copy-pasteable and reproduces locally against a MiniStack on the default port.

## The CDK vertical (self-provisioning — #147)

This vertical **owns and self-provisions its own CDK app + stack**, fully
decoupled from the demo stack `lib/ministack-stack.ts` (the "compat = proof" half
of the sample-vs-proof split). Full file-level detail lives in
[`iac/cdk/README.md`](iac/cdk/README.md); in brief:

- **`iac/cdk/construct.ts`** — `DoublerFunction`, a standalone reusable
  construct that mirrors the hardened `cdk-doubler` in
  [`lib/ministack-stack.ts`](../../lib/ministack-stack.ts): Node 24 runtime, the
  repo-root `lambda/` asset + `index.handler`, a least-privilege
  customer-managed role, a KMS-encrypted log group on a rotated CMK, a DLQ on
  its own rotated CMK, and reserved concurrency. It documents/proves the
  hardened pattern the harness exposes. Under `iac/**` but not named
  `deploy.ts`, so it is **coverage-gated at 100%** and fully exercised by the
  pure-synth unit test
  [`test/unit/services/lambda-construct.test.ts`](../../test/unit/services/lambda-construct.test.ts)
  (mirrors `test/unit/stack.test.ts`).
- **`iac/cdk/stack.ts`** — `CompatLambdaStack`, this vertical's own `cdk.Stack`.
  It instantiates `DoublerFunction` under the **distinct** physical name
  `compat-lambda-doubler` so it never collides with the demo `cdk-doubler` in
  MiniStack's single global namespace. Pinned to `MINISTACK_ENV`. **100%-gated**.
- **`iac/cdk/app.ts`** — `buildCompatApp()`, the per-vertical CDK app entrypoint
  (owned by the vertical, NOT `bin/app.ts`); attaches cdk-nag via the v3
  `Validations.of(app).addPlugins(...)` API. **100%-gated**.
- **`iac/cdk/deploy.ts`** — `cdkLambda: DeployAdapter<LambdaContract>`.
  `deploy()` is **verify-or-provision**: `GetFunction` for
  `compat-lambda-doubler` (fast path, no redeploy); on
  `ResourceNotFoundException` it runs `cdk bootstrap` + `cdk deploy
CompatLambdaStack` via the compat app. No `teardown` — cross-vertical reset is
  `POST /_ministack/reset` and the adapter must not tear down the demo stack.

## Coverage

Per the merged `jest.config.js` path-convention excludes (no per-vertical config
edits needed), and the harness-wide **extract-don't-mock** policy in
[`../README.md` § Coverage](../README.md#coverage):

- `checks.sdk.ts`, `checks.cli.ts` (`checks.*.ts`) and `iac/cdk/deploy.ts`
  (`iac/**/deploy.ts`) are **THIN I/O shells** run only in the **integration
  tier** against a live MiniStack, so istanbul can't instrument them —
  **coverage-EXCLUDED**. Their pure logic is extracted to gated siblings.
- `invoke.ts` is the extracted PURE seam for both oracles (#151/#144):
  `buildSdkPayload` (SDK `Payload` bytes), `parseInvokePayload` (decode the SDK
  `Uint8Array` / CLI temp-file string response), and `cliInvokeArgs` (the exact
  `aws lambda invoke` argv). It is NOT named `checks.*.ts`, so it is
  **coverage-INCLUDED / 100%-gated**, held there by
  [`lambda-invoke.test.ts`](../../test/unit/services/lambda-invoke.test.ts) —
  which locks the [#136](https://github.com/scottschreckengaust/e2e-ministack/issues/136)
  `--payload` double-encoding bug as a permanent emulator-free regression test.
- `health.ts` (`isFunctionConfigHealthy` / `hasProvenanceMarker`) is the pure
  classification the deploy adapter delegates to → **100%-gated** by
  [`lambda-health.test.ts`](../../test/unit/services/lambda-health.test.ts).
- `contract.ts` is types-only → erases to zero runtime statements.
- `iac/cdk/construct.ts`, `iac/cdk/stack.ts`, and `iac/cdk/app.ts` are pure
  synth logic → **100%-gated**, held there by `lambda-construct.test.ts` and
  `lambda-compat-stack.test.ts`.

The integration matrix's correctness — the thin shells end-to-end — is verified
by CI's **Integration (MiniStack)** job on the PR (it cannot run locally without
an emulator). The unit tier proves the extracted pure logic; nothing is mocked
to fabricate coverage.

## MiniStack Lambda boundary notes

- MiniStack executes Lambda in **real Docker sibling containers**
  (`LAMBDA_EXECUTOR=docker` + the mounted host Docker socket + `--network host`
  — see [AGENTS.md](../../AGENTS.md) "Why these flags"). The `nodejs24.x`
  runtime works end-to-end against the pinned image, which is why `nodeVersion`
  matches `/^v24\./`.
- Both invocations use the default `RequestResponse` type: a handler that
  _returns_ a 400 envelope (as `cdk-doubler` does for non-numeric input) yields
  HTTP `StatusCode` 200 with `FunctionError` undefined and the 400 inside the
  payload — an unhandled _throw_ would instead set `FunctionError:'Unhandled'`.
  Both oracles assert `FunctionError` (SDK) / `statusCode` (CLI) accordingly.
- No additional Lambda-emulation limitation was discovered for this
  reservation-blind invoke path. Axis-1 breadth for Lambda is recorded as
  `supported` in
  [`services/_registry/ministack-support.json`](../_registry/ministack-support.json);
  this vertical adds the Axis-2 `lambda × AWS::Lambda::Function × cdk` row to
  [`provisioning.json`](../_registry/provisioning.json).

## Upstream references

- MiniStack supported services (Lambda): <https://github.com/ministackorg/ministack#supported-services>
- AWS CLI `lambda invoke`: <https://docs.aws.amazon.com/cli/latest/reference/lambda/invoke.html>
- `@aws-sdk/client-lambda` `InvokeCommand`: <https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/lambda/command/InvokeCommand/>
