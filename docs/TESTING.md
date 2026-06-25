# Testing Strategy

This is the canonical, single source of truth for how `e2e-ministack` is
tested. It supersedes the short "Test pyramid" note in
[`CLAUDE.md`](../CLAUDE.md).

## Not a pyramid — a matrix

The classic "test pyramid" stacks tiers vertically (lots of unit, fewer
integration, a sliver of E2E). That framing hides the fact that testing has
several **independent quality dimensions** that run in parallel, not on top of
each other. A fast unit test and a load test answer different questions; one
does not "sit above" the other. We therefore reason about a **testing matrix**:

- **Functional** — does the code do the right thing? (logic, contracts, infra
  shape)
- **Performance / Load** — does it hold up under throughput and stay within
  latency/error budgets?
- **Security** — is the synthesized infrastructure and source safe?
- **Acceptance (UAT) / functional E2E** — does the deployed system behave
  correctly end to end, from a user's vantage point?
- **Cross-platform / Mobile** — does any user-facing surface work across
  browsers and real mobile OSes?

Each dimension has its own tooling and its own gate. Some are implemented
today; others are planned or still TBD. Nothing below is implied to exist
unless its **Status** says **Implemented**.

## Matrix

| Dimension                         | Tier / Tool                                                                            | What it gates                                                                                                                                                                                                                                      | Status                                            |
| --------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Functional — logic                | unit tier — Jest (`test/unit/lambda.test.ts`)                                          | Pure `lambda/index.js` handler logic (doubles `event.n`, returns `process.version`)                                                                                                                                                                | **Implemented**                                   |
| Functional — infra                | unit tier — Jest + CDK `Template` (`test/unit/stack.test.ts`)                          | Fine-grained CDK assertions (security/structural intent), a **full-template `toMatchSnapshot`** (volatile Lambda asset hash masked, #42), **and** a fast-tier cdk-nag `AwsSolutions` assertion via `validateScope(stack)`; synth-only, no emulator | **Implemented**                                   |
| Functional — properties           | unit tier — fast-check (`@fast-check/jest`)                                            | Property tests over the handler; **seed pinned** in `test/setup.fast-check.ts` for reproducible gates                                                                                                                                              | **Implemented**                                   |
| Functional — robustness           | mutation — Stryker (`npm run test:mutation`)                                           | Mutates `lambda/index.js` against the unit tier; CI breaks under **80%** (currently 100%)                                                                                                                                                          | **Implemented**                                   |
| Functional — robustness           | fuzzing — jazzer.js (`fuzz/handler.fuzz.js`, `npm run fuzz`)                           | Coverage-guided fuzz: handler never throws, never returns a non-finite `doubled`. Scheduled / `workflow_dispatch` only; needs GLIBC ≥ 2.38                                                                                                         | **Implemented**                                   |
| Functional — integration          | integration tier — Jest + AWS SDK v3 (`test/integration/`)                             | Exercises deployed MiniStack resources via `AWS_ENDPOINT_URL`; assumes `cdk deploy` already ran                                                                                                                                                    | **Implemented**                                   |
| Security — IaC / SAST             | cdk-nag, checkov, cfn-lint, Semgrep, CodeQL, Gitleaks, OSV-Scanner, Grype, `npm audit` | Synthesized template + source/supply-chain scans (see `CLAUDE.md` "Security checks")                                                                                                                                                               | **Implemented**                                   |
| Performance / Load                | Apache JMeter via **jmeter-java-dsl** (Apache-2.0)                                     | Lambda Invoke API on MiniStack (dummy SigV4); hard-gate p50/p95/p99 + error-rate SLOs; later Phase-2 SPC/control-chart for latency drift                                                                                                           | **Planned** (issue #73; lint sub-issue #74)       |
| Acceptance (UAT) / functional E2E | Playwright (Apache-2.0; multi-engine incl. WebKit; video/screenshot/trace)             | Real-account functional + visual E2E of any user-facing surface                                                                                                                                                                                    | **TBD**                                           |
| Cross-platform / Mobile           | Appium (+ simulators/emulators or a device cloud)                                      | Real iOS/Android OS coverage                                                                                                                                                                                                                       | **TBD**                                           |
| Security — runtime / pentest      | Penetration testing; CSPM (ScoutSuite/Prowler)                                         | Live-account posture (needs a real AWS account; see `CLAUDE.md`)                                                                                                                                                                                   | **TBD**                                           |
| Functional — real account E2E     | e2e tier — Jest (`test/e2e/e2e.test.ts`)                                               | Deploy to a real account and assert on live resources                                                                                                                                                                                              | **TBD** — currently a `describe.skip` placeholder |

## Implemented today

The functional and security dimensions are real and gating in CI
(`.github/workflows/ci.yml` for unit + integration; `.github/workflows/security.yml`
for the scanners). `jest.config.js` selects a tier directory via the
`JEST_TIER` env var, set by the npm scripts:

- `npm run test:unit` — logic + CDK fine-grained assertions + full-template
  snapshot + fast-tier cdk-nag assertion + fast-check properties (no
  emulator/Docker). The snapshot baseline lives in `test/unit/__snapshots__/`
  and is updated with `npm run test:unit -- -u` after an intended template
  change.
- `npm run test:integration` — AWS SDK v3 against deployed MiniStack resources.
- `npm run test:mutation` — Stryker over the Lambda logic (≥ 80% gate).
- `npm run fuzz` — jazzer.js libFuzzer target (scheduled job, not a fast gate).
- `npm run test:e2e` — runs the `describe.skip` placeholder (no real-account
  stage yet).

Mutation testing is scoped to `lambda/index.js` only; the CDK stack is
declarative config Stryker can't tie to synth output, so the infra is covered
by cdk-nag/checkov plus the fine-grained CDK `Template` assertions and the
full-template snapshot instead.

> **Two senses of "snapshot."** The infra snapshot above is a **Jest
> fine-grained / full-template snapshot** — `Template.fromStack(...).toJSON()`
> compared via `toMatchSnapshot`, the assertion-style technique in the
> [CDK testing guide](https://docs.aws.amazon.com/cdk/v2/guide/testing.html).
> It is **synth-only** (no deploy). This is distinct from the
> [`@aws-cdk/integ-tests-alpha` `IntegTest`](https://github.com/aws-samples/aws-cdk-examples/blob/main/SNAPSHOT_TESTING.md)
> harness, which **deploys** a stack and snapshots the result — that
> deploy-and-compare style is **not** used here (it would belong to the
> real-account E2E dimension, currently TBD).

## Planned — Load / performance (issue #73)

A FOSS load-testing gate is planned to exercise the `cdk-doubler` Lambda's
Invoke API on MiniStack:

- **Tool:** Apache **JMeter**, authored with **jmeter-java-dsl** (code-as-test,
  Apache-2.0) rather than hand-maintained `.jmx` XML.
- **Target:** the Lambda Invoke API on MiniStack, signed with **dummy SigV4**
  (MiniStack accepts `test`/`test` credentials).
- **Gate:** hard-fail on percentile-latency and error-rate SLOs (p50/p95/p99 +
  error rate), following the produce → always-upload → enforce pattern used by
  the other CI gates so the report artifact survives a failing run.
- **Phase 2:** a statistical-process-control / control-chart view to catch
  latency _drift_ over time, not just a single-run threshold breach.
- A companion **Java/Kotlin zero-tolerance lint + static-analysis gate** for the
  DSL tier is tracked as sub-issue **#74**.

This dimension is **not implemented yet**; the matrix marks it **Planned**.

## TBD — Acceptance, visual, and mobile

These are aspirational and depend on a real user-facing surface and/or a real
AWS account, neither of which exists in this repo today:

- **User-acceptance / functional E2E + visual** — **Playwright** (Apache-2.0,
  multi-engine including WebKit, with video/screenshot/trace artifacts) is the
  intended tool.
- **Real mobile** — **Appium** driving simulators/emulators (or a commercial
  device cloud — not FOSS). **Caveat:** Playwright, Cypress, and k6-browser
  emulate **viewports**, not a real mobile OS. Only Appium + simulators/emulators
  (or a paid device cloud) exercises a genuine iOS/Android operating system.
- **Penetration testing** and **runtime CSPM** (ScoutSuite/Prowler) — meaningful
  only against a deployed real-account stage; see the "Not used here" note in
  [`CLAUDE.md`](../CLAUDE.md).

## Tooling principles

- **FOSS + permissive licenses preferred.** JMeter and jmeter-java-dsl are
  Apache-2.0; Playwright and Appium are Apache-2.0. **k6 was rejected** for the
  load-testing role partly because of its AGPL-3.0 license plus single-vendor
  relicensing risk.
- **Everything pinnable is pinned.** Any tool added here follows
  [`docs/PINNING.md`](./PINNING.md) — exact versions, SHAs, or digests, governed
  by the lockfile (`npm ci`, never `npm install`).
- **Zero-tolerance gates.** Hard-fail tools use the produce → always-upload →
  enforce pattern so the diagnostic artifact (SARIF / JUnit / HTML / text) is
  available precisely when a job fails.
