# MiniStack compatibility harness (`services/`)

The reusable, evidence-backed mechanism that answers, per resource: **"does
MiniStack emulate service X, and can IaC tool Y actually provision + exercise
it?"** — grown one service at a time and re-evaluated when the pinned MiniStack
image digest bumps. This directory is the foundation (epic
[#117](https://github.com/scottschreckengaust/e2e-ministack/issues/117),
sub-issue A / [#135](https://github.com/scottschreckengaust/e2e-ministack/issues/135));
per-service depth arrives in later sub-issues (#136+).

> **Operator guide:** the upstream-tracking flow — how a red/partial verdict is
> connected to an `ministackorg/ministack` issue/PR (query = automated) and how
> a maintainer optionally comments upstream (comment/watch = human-gated) —
> lives in [`docs/MINISTACK-COMPAT.md`](../docs/MINISTACK-COMPAT.md).

## The two-axis model

Compatibility is recorded on two orthogonal axes, kept in separate registries
under [`_registry/`](./_registry/):

- **Axis 1 — API breadth** (`ministack-support.json`): _does MiniStack emulate
  the service's API at all?_ This is tool-independent and derived statically
  from MiniStack's own source/README (MiniStack is open source, so its source
  is the source of truth). Authored up front for the full target scope, one row
  per service, each row citing checkable evidence.
- **Axis 2 — provisioning depth** (`provisioning.json`): _for a given
  `(service × resource × iac)`, does it deploy, and do the behavioral oracles
  pass?_ This is the e2e truth layer. It starts **empty** and is grown one
  vertical at a time; each row records the MiniStack image digest it was
  verified against (`lastVerifiedDigest`), which makes the registry
  **self-invalidating** on a version bump.

Why two axes: **the behavioral oracle is IaC-tool-agnostic.** Once a Lambda
exists in MiniStack, `aws lambda invoke` behaves identically whether CDK,
Terraform, CloudFormation, or Cloud Control API created it. So behavioral
checks are defined **once per service** and shared across every tool; only
**provisioning** differs per tool. That is a finding machine: a resource can be
green under Terraform yet red under CDK (CloudFormation resource-type coverage
lags raw API coverage), and the harness records those as distinct Axis-2 rows
against one identical oracle.

## The seam: `Contract` + `DeployAdapter`

Both interfaces live in [`_harness/adapter.ts`](./_harness/adapter.ts):

- A **`Contract`** is the typed handle to a provisioned resource. Each vertical
  narrows it to the minimal shape its oracles need, e.g.
  `type LambdaContract = Contract & { functionName: string }`.
- A **`DeployAdapter<C>`** **verify-or-provisions** the resource and returns
  that `Contract`. One adapter per `(service × IaC tool)`; the returned contract
  is the only thing that crosses the deploy⇄verify boundary, which is what keeps
  the oracles tool-agnostic. `deploy()` verifies the resource exists (fast path,
  no rework) and provisions it if absent — see
  [Per-vertical self-provisioning](#per-vertical-self-provisioning-147) below.

## Layout (service-primary, IaC-nested)

```text
services/
  README.md                       # this file
  _harness/
    adapter.ts                    # Contract + DeployAdapter<C> (shared, types-only)
  _registry/
    ministack-support.json        # Axis 1 — API breadth (evidence-backed)
    ministack-support.schema.json
    provisioning.json             # Axis 2 — provisioning depth (starts empty)
    provisioning.schema.json
    ministack-pin.json            # MiniStack image digest the catalog was verified against
  <service>/                      # one dir per service (added by #136+)
    README.md                     # coverage, boundaries found, upstream refs
    contract.ts                   # e.g. LambdaContract
    checks.sdk.ts                 # shared SDK v3 oracle   (integration tier)
    checks.cli.ts                 # shared `aws <svc> ...` oracle (integration tier)
    iac/
      cdk/            construct.ts + stack.ts + app.ts + deploy.ts  # vertical owns its OWN app/stack (#147)
      terraform/      main.tf      + deploy.ts   (reserved)
      cloudformation/ template.yaml + deploy.ts  (reserved)
```

Behavioral tests live in `test/integration/services/<service>.test.ts`
(`describe.each(adapters) × it.each(oracles)`) and emit named JUnit cases to
`reports/junit/integration.xml`.

## Both registries are schema-gated in the unit tier

`test/unit/registry.test.ts` validates both JSON files against their JSON
Schemas with [`ajv`](https://ajv.js.org/) (MIT), mirroring the existing
`test/unit/license-verdict.test.ts` pattern. A malformed or half-authored row
fails the fast unit gate, so the source-of-truth registry **can't rot**. This
test is pure logic and needs no emulator. Verdict flips are reviewed as PR
diffs — never auto-committed by CI.

## How to add a service

1. **Axis-1 row (breadth):** add a row to `_registry/ministack-support.json`
   with a source-verified `status`
   (`supported | partial | unsupported | upstream-tracked`), a human-readable
   `evidence` string, a checkable `evidenceUrl` (a MiniStack source/README
   anchor), and `ministackRef` (`owner/repo#N` when `upstream-tracked`, else
   `null`). Add the service key to `EXPECTED_SERVICES` in
   `test/unit/registry.test.ts`.
2. **Vertical (depth, #136+):** create `services/<service>/` with `contract.ts`,
   the shared `checks.sdk.ts` / `checks.cli.ts` oracles, and — per IaC tool —
   the tool's OWN self-provisioned artifact(s) plus its
   `iac/<tool>/deploy.ts` adapter. For CDK that is a `construct.ts` + `stack.ts`
   (a `Compat*Stack` with a distinct `compat-*` physical name) + `app.ts`
   (the per-vertical CDK app), whose `deploy()` verify-or-provisions that stack;
   for Terraform it is `main.tf` + `deploy.ts`, and so on. Wire the adapter(s)
   into `test/integration/services/<service>.test.ts`. **Do NOT add the
   resource-under-test to `lib/ministack-stack.ts`** — that is the decoupled
   sample; the vertical is the proof (see
   [Per-vertical self-provisioning](#per-vertical-self-provisioning-147)).
3. **Axis-2 rows:** the vertical appends `(service × resource × iac)` result
   rows to `_registry/provisioning.json`, each stamped with the current
   `lastVerifiedDigest`.

## Per-vertical self-provisioning (#147)

Each vertical **owns and self-provisions its own IaC artifact(s)** — the harness
does **not** depend on the demo stack `lib/ministack-stack.ts`. This is the
`sample` vs `proof` split, locked on
[#147](https://github.com/scottschreckengaust/e2e-ministack/issues/147):

- **`lib/` = decoupled sample.** `lib/ministack-stack.ts` stays the repo's
  minimal "trivial demo" (two S3 buckets + one Lambda) with its own
  `test/integration/integration.test.ts`. It is never extended to hold
  resources-under-test.
- **compat verticals = proof.** Each `services/<svc>/iac/<tool>/` owns its own
  app(s)/stack(s) and provisions them itself. The Lambda/CDK vertical (the pilot)
  ships `stack.ts` (`CompatLambdaStack`, function `compat-lambda-doubler`) and
  `app.ts` (`buildCompatApp()`); its `deploy()` verify-or-provisions that stack
  against a live MiniStack.

**Topology-agnostic.** A vertical may own **any** shape — a single stack,
multiple stacks, nested stacks, or cross-app-via-outputs — and its
`DeployAdapter.deploy()` provisions whatever it owns and returns the `Contract`.
The `DeployAdapter` and `Contract` interfaces are **UNCHANGED**; provisioning is
entirely the adapter's concern, which is exactly what keeps the SDK/CLI oracles
IaC-tool-agnostic. Distinct `compat-*` physical names avoid collisions with the
demo stack in MiniStack's single global namespace.

**Verify-or-provision.** `deploy()` verifies the resource exists (fast path — no
redeploy on warm re-runs) and provisions it if absent. It works standalone on a
fresh MiniStack with **no** prior `cdk deploy` of the demo stack. Cross-vertical
reset uses `POST /_ministack/reset` (the upstream pattern); an adapter must never
tear down what it did not provision.

Downstream verticals inherit this pilot pattern: **[S3
(#139)](https://github.com/scottschreckengaust/e2e-ministack/issues/139)** builds
its own `CompatS3Stack` and **[DynamoDB
(#140)](https://github.com/scottschreckengaust/e2e-ministack/issues/140)** its own
`CompatDynamoStack` — **NOT** additions to `lib/ministack-stack.ts`. Other IaC
tools (Terraform / SAM / CloudFormation / AWS Blocks) are separate future
issue/PR paths.

## Coverage

`services/` **source** is held to the repo's 100% coverage gate in the fast
unit tier (same as `lib/` and `bin/`). But the code that only runs in the
**integration tier** is excluded from coverage collection, because it executes
against a live MiniStack (e.g. inside its Lambda container) where istanbul
can't instrument it — the same reason the integration tier collects zero
coverage today. `jest.config.js` `collectCoverageFrom` encodes this as
**path-convention** excludes, so new verticals need no further config edits:

- `services/**/checks.*.ts` — the SDK/CLI oracles (integration tier)
- `services/**/iac/**/deploy.ts` — the `DeployAdapter`s (integration-tier provisioners)
- `services/**/*.test.ts` — spec files

### The policy: extract pure logic to a gated module — never mock to chase coverage (#151 / #144)

The exclusion is for **genuine I/O**, not a license to leave logic untested. The
harness-wide rule every vertical follows:

> **Extract pure logic to a gated (coverage-included) module; keep only genuine
> I/O in the excluded shell; never mock the emulator / CLI / SDK to chase
> coverage.**

This is the pattern PR #148 established (the deploy adapter's repoRoot/argv/env
logic → `_harness/cdk.ts` + `_harness/aws-env.ts`, its health classification →
`<service>/health.ts`) and #151/#144 extended to the oracles: the payload
encoding, response parsing, and AWS-CLI argv that used to live INSIDE
`checks.sdk.ts` / `checks.cli.ts` now live in `services/lambda/invoke.ts`, a
NON-`checks.*.ts` module that `collectCoverageFrom` therefore INCLUDES and gates
at 100%. That seam is exactly where the [#136] AWS-CLI-v2 `--payload`
double-encoding bug lived — an emulator-free unit test now locks it as a
permanent regression, and mutation testing (Stryker) proves the tests pin the
behavior. The genuine I/O (`LambdaClient.send`, `execFile('aws', …)`, the
temp-file lifecycle) stays in the thin, excluded shell.

Why not mock: mocking MiniStack / the AWS CLI / the SDK in the unit tier would
manufacture a green number without proving the real wire behavior (and would let
a regression like #136 slip past a mock that encodes the same wrong assumption).
The **required Integration (MiniStack) job** proves the shells end-to-end against
a live emulator; the unit tier proves the extracted pure logic. Downstream
verticals ([S3 #139], [DynamoDB #140], and future IaC tools) inherit this by
convention — no `jest.config.js` edit is needed, because a helper named anything
but `checks.*.ts` / `iac/**/deploy.ts` is coverage-included automatically.

[#136]: https://github.com/scottschreckengaust/e2e-ministack/issues/136
[S3 #139]: https://github.com/scottschreckengaust/e2e-ministack/issues/139
[DynamoDB #140]: https://github.com/scottschreckengaust/e2e-ministack/issues/140

### What each excluded / trivially-covered file is, and why

Everything else under `services/` (any `construct.ts` / `stack.ts` / `app.ts`
synth logic, `health.ts`, `invoke.ts`, and the `_harness/*` helpers) is gated at
100%. Held there by `test/unit/services/*.test.ts` (no emulator). Any executable
pure logic you add must be exercised by a unit test to hold 100%. The
deliberately-uncovered files, one rationale each, so the exclude list is
self-explaining:

- `services/**/checks.*.ts` (the SDK/CLI oracles) — coverage-EXCLUDED by
  design: what remains after extraction is genuine I/O (`LambdaClient.send`,
  `execFile('aws', …)`, temp-file read/unlink) that only runs against a live
  MiniStack in the integration tier, where istanbul can't see it. Proven by the
  Integration (MiniStack) job, not the unit gate.
- `services/**/iac/**/deploy.ts` (the `DeployAdapter`s) — coverage-EXCLUDED by
  design: after #148 extracted its pure logic (`_harness/cdk.ts`,
  `_harness/aws-env.ts`, `<service>/health.ts`), the shell is only the live
  `LambdaClient`/`GetFunction`, the `ResourceNotFoundException`→absent mapping
  (a catch clause inseparable from the live `send`, not a standalone predicate),
  and the two `cdk` `execFile` calls — all integration-tier I/O. Audited under
  #151: no classifiable pure logic remains to extract.
- `services/_harness/adapter.ts` and `services/<service>/contract.ts` —
  types-only (`interface`/`type` declarations): they erase to ZERO runtime
  statements, so they carry no executable code to cover and trivially satisfy
  the gate. Not excluded by a glob — they simply contribute nothing.
