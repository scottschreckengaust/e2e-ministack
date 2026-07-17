# DynamoDB vertical (`services/dynamodb/`)

The third service vertical of the MiniStack compatibility harness (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
[#140](https://github.com/scottschreckengaust/e2e-ministack/issues/140)). It
proves the harness on **DynamoDB × CDK** with **both** oracles, a structural
clone of the [Lambda vertical](../lambda/README.md) and the
[S3 vertical](../s3/README.md).

Unlike Lambda/S3 (which mirror a construct that already exists inline in
`lib/ministack-stack.ts`), this vertical **authors a fresh hardened resource** —
a `dynamodb.Table` hardened until the cdk-nag AwsSolutions pack passes clean —
which is exactly the "harden a new construct" path epic #117 wanted a third
service to exercise.

## Layout

```text
services/dynamodb/
  README.md          # this file
  contract.ts        # DynamoContract = Contract & { tableName: string } (types-only)
  health.ts          # isTableHealthy + hasProvenanceMarker predicates (100%-gated)
  checks.sdk.ts      # checkSdk — typed AWS SDK v3 oracle   (defined ONCE, integration tier)
  checks.cli.ts      # checkCli — documented AWS CLI oracle  (defined ONCE, integration tier)
  iac/
    cdk/
      construct.ts   # HardenedTable — reusable hardened DynamoDB table (100%-gated)
      stack.ts       # CompatDynamoStack — self-provisioned compat stack (100%-gated)
      app.ts         # buildCompatApp — per-vertical CDK app entrypoint (100%-gated)
      deploy.ts      # cdkDynamo: DeployAdapter<DynamoContract> (verify-or-provision, integration tier)
      README.md
    terraform/       # RESERVED — README stub only (future sub-issue)
    cloudformation/  # RESERVED — README stub only (future sub-issue)
```

The behavioral matrix lives in
[`test/integration/services/dynamodb.test.ts`](../../test/integration/services/dynamodb.test.ts):
`describe.each(adapters) × it.each(oracles)`. With `adapters = [cdkDynamo]` and
`oracles = { sdk, cli }` it emits the named JUnit cases
`dynamodb provisioned via cdk › passes the sdk oracle` and `… passes the cli
oracle` to `reports/junit/integration.xml`.

## The two oracles (provisioner-blind, defined once)

Both take only a `DynamoContract` (the table name) and never know which IaC tool
created the table — that indirection is what lets one oracle pair be shared
across CDK, Terraform, and CloudFormation. Each does a full item **round-trip**
against the deployed table:

- **`checkSdk`** — via `@aws-sdk/client-dynamodb`: `PutItem` an item under a
  unique partition-key value carrying a `payload` attribute, `GetItem` it back
  with a `ConsistentRead`, assert the payload round-trips, then `DeleteItem` in a
  `finally` (idempotent against a reused emulator, issue #10). The partition-key
  attribute name comes from the construct's `COMPAT_DYNAMO_PARTITION_KEY` (single
  source of truth), so the oracle can never drift from the deployed schema.
- **`checkCli`** — the EXACT commands a human pastes into AWS CloudShell:
  `aws dynamodb put-item --table-name <name> --item '<json>'` then
  `aws dynamodb get-item --table-name <name> --key '<json>' --consistent-read`,
  then compare the returned payload. The item is deleted afterward. Args are
  passed to `execFile` as an argv array (never a shell string) — no shell, no
  injection surface; the item/key JSON is built with `JSON.stringify`.

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

- **`iac/cdk/construct.ts`** — `HardenedTable`, a standalone reusable construct
  that authors a fresh hardened `dynamodb.Table`: **point-in-time recovery**
  (cdk-nag AwsSolutions-DDB3), **customer-managed KMS encryption** on a rotated
  CMK (checkov CKV_AWS_119), **PAY_PER_REQUEST** billing, and a `DESTROY` removal
  policy. Its partition key is the distinctive `COMPAT_DYNAMO_PARTITION_KEY`,
  which doubles as the vertical's **primary provenance marker**. **100%-gated**,
  exercised by
  [`test/unit/services/dynamodb-construct.test.ts`](../../test/unit/services/dynamodb-construct.test.ts).
- **`iac/cdk/stack.ts`** — `CompatDynamoStack`, this vertical's own `cdk.Stack`,
  instantiating `HardenedTable` under the **distinct** physical name
  `compat-dynamo-table` (`COMPAT_DYNAMO_TABLE_NAME`) so it never collides in
  MiniStack's single global namespace. Pinned to `MINISTACK_ENV`. **100%-gated**.
- **`iac/cdk/app.ts`** — `buildCompatApp()`, the per-vertical CDK app entrypoint
  (owned by the vertical, NOT `bin/app.ts`); attaches cdk-nag via the v3
  `Validations.of(app).addPlugins(...)` API. **100%-gated**.
- **`iac/cdk/deploy.ts`** — `cdkDynamo: DeployAdapter<DynamoContract>`.
  `deploy()` is **verify-or-provision**: `DescribeTable` for `compat-dynamo-table`
  (fast path, no redeploy); on `ResourceNotFoundException` it runs `cdk bootstrap`
  then `cdk deploy CompatDynamoStack`; then on BOTH paths it reads the table back
  and asserts the provenance marker (below). No `teardown`.

## Provenance marker (mirrors #175)

A bare verify-short-circuit would let the oracle green against a **stale or
foreign** table that merely shares the name `compat-dynamo-table`, never
exercising a freshly-provisioned `HardenedTable`. So `deploy()` stamps a
distinctive **partition key** (`COMPAT_DYNAMO_PARTITION_KEY`) that ONLY this
stack sets, then reads it back via `DescribeTable` on both the fast-path skip and
after a fresh provision and **fails loudly** if the live table's HASH key is not
that marker. The partition key is the chosen primary marker because
`DescribeTable` returns `KeySchema` reliably on MiniStack, whereas tags are a
side table (`ListTagsOfResource`) the emulator may not surface; a secondary CDK
tag (`COMPAT_DYNAMO_PROVENANCE_TAG`) is applied belt-and-braces. The pure
read-back predicate (`hasProvenanceMarker`) lives in the 100%-gated `health.ts`.

## Coverage

Per the merged `jest.config.js` path-convention excludes (no per-vertical config
edits needed):

- `checks.sdk.ts`, `checks.cli.ts` (`checks.*.ts`) and `iac/cdk/deploy.ts`
  (`iac/**/deploy.ts`) run only in the **integration tier** against a live
  MiniStack, so istanbul can't instrument them — **coverage-EXCLUDED**.
- `contract.ts` is types-only → erases to zero runtime statements.
- `health.ts`, `iac/cdk/construct.ts`, `iac/cdk/stack.ts`, and `iac/cdk/app.ts`
  are pure logic/synth → **100%-gated**, held there by
  `dynamodb-health.test.ts`, `dynamodb-construct.test.ts`, and
  `dynamodb-compat-stack.test.ts`.

The integration matrix's correctness is verified by CI's **Integration
(MiniStack)** job on the PR (it cannot run locally without an emulator).

## MiniStack DynamoDB boundary notes

- MiniStack serves DynamoDB on the single local endpoint (port 4566), reached via
  the generic `AWS_ENDPOINT_URL`. This vertical proves `CreateTable` (via `cdk
deploy`), `DescribeTable`, `PutItem`, and `GetItem`.
- **Streams / TTL are NOT exercised** (a #140 non-goal). If a later issue needs
  them, extend the oracles; today the boundary is item put/get + table describe.
- Axis-1 breadth for DynamoDB is recorded as `supported` in
  [`services/_registry/ministack-support.json`](../_registry/ministack-support.json);
  this vertical adds the Axis-2 `dynamodb × AWS::DynamoDB::Table × cdk` row to
  [`provisioning.json`](../_registry/provisioning.json).

## Upstream references

- MiniStack supported services (DynamoDB): <https://github.com/ministackorg/ministack#supported-services>
- AWS CLI `dynamodb put-item` / `get-item`: <https://docs.aws.amazon.com/cli/latest/reference/dynamodb/>
- `@aws-sdk/client-dynamodb` `PutItemCommand` / `GetItemCommand`: <https://docs.aws.amazon.com/AWSJavaScriptSDK/v3/latest/client/dynamodb/>
