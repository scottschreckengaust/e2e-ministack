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

| Dimension                         | Tier / Tool                                                                                         | What it gates                                                                                                                                                                                                                                | Status                                            |
| --------------------------------- | --------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| Functional — logic                | unit tier — Jest (`test/unit/lambda.test.ts`)                                                       | Pure `lambda/index.js` handler logic (doubles `event.n`, returns `process.version`)                                                                                                                                                          | **Implemented**                                   |
| Functional — infra                | unit tier — Jest + CDK `Template` (`test/unit/stack.test.ts`)                                       | Fine-grained CDK assertions (security/structural intent) **and** a fast-tier cdk-nag `AwsSolutions` assertion via `validateScope(stack)`; synth-only, no emulator                                                                            | **Implemented**                                   |
| Functional — infra snapshot       | integ — `@aws-cdk/integ-runner` (`integ/integ.ministack-stack.ts`)                                  | Cloud-assembly snapshot baseline in `integ/*.js.snapshot/`; synth-only PR gate via `npm run test:integ-snapshot`; refresh with `npm run test:integ-snapshot:update` on MiniStack (#168)                                                      | **Implemented**                                   |
| Functional — properties           | unit tier — fast-check (`@fast-check/jest`)                                                         | Property tests over the handler; **seed pinned** in `test/setup.fast-check.ts` for reproducible gates                                                                                                                                        | **Implemented**                                   |
| Functional — robustness           | mutation — Stryker (`npm run test:mutation`)                                                        | Mutates the scoped logic against the unit tier; the bar is **zero surviving mutants** (`break: 100` in `stryker.config.mjs`)                                                                                                                 | **Implemented**                                   |
| Functional — robustness           | fuzz regression — corpus replay (`fuzz/handler.regression.test.js`, `npm run test:fuzz-regression`) | Replays the committed `fuzz/corpus/` seeds through the handler as plain Jest tests (same invariants); emits `reports/junit/fuzz.xml`. Runs in the **PR-gating unit path**; a pinned crash input fails the tier. Plain Jest (no native addon) | **Implemented**                                   |
| Functional — robustness           | fuzzing — jazzer.js (`fuzz/handler.fuzz.js`, `npm run fuzz`)                                        | Coverage-guided fuzz: handler never throws, never returns a non-finite `doubled`. **Exploratory**, schedule / `workflow_dispatch` only; needs GLIBC ≥ 2.38                                                                                   | **Implemented**                                   |
| Functional — integration          | integration tier — Jest + AWS SDK v3 (`test/integration/`)                                          | Exercises deployed MiniStack resources via `AWS_ENDPOINT_URL`; assumes `cdk deploy` already ran                                                                                                                                              | **Implemented**                                   |
| Security — IaC / SAST             | cdk-nag, checkov, cfn-lint, Semgrep, CodeQL, Gitleaks, OSV-Scanner, Grype, `npm audit`              | Synthesized template + source/supply-chain scans (see [`AGENTS.md`](../AGENTS.md) Security checks)                                                                                                                                           | **Implemented**                                   |
| Performance / Load                | Apache JMeter via **jmeter-java-dsl** (Apache-2.0)                                                  | Lambda Invoke API on MiniStack (dummy SigV4); hard-gate p50/p95/p99 + error-rate SLOs; later Phase-2 SPC/control-chart for latency drift                                                                                                     | **Planned** (issue #73; lint sub-issue #74)       |
| Acceptance (UAT) / functional E2E | Playwright (Apache-2.0; multi-engine incl. WebKit; video/screenshot/trace)                          | Real-account functional + visual E2E of any user-facing surface                                                                                                                                                                              | **TBD**                                           |
| Cross-platform / Mobile           | Appium (+ simulators/emulators or a device cloud)                                                   | Real iOS/Android OS coverage                                                                                                                                                                                                                 | **TBD**                                           |
| Security — runtime / pentest      | Penetration testing; CSPM (ScoutSuite/Prowler)                                                      | Live-account posture (needs a real AWS account; see [`AGENTS.md`](../AGENTS.md))                                                                                                                                                             | **TBD**                                           |
| Functional — real account E2E     | e2e tier — Jest (`test/e2e/e2e.test.ts`)                                                            | Deploy to a real account and assert on live resources                                                                                                                                                                                        | **TBD** — currently a `describe.skip` placeholder |

## Implemented today

The functional and security dimensions are real and gating in CI
(`.github/workflows/ci.yml` for unit + integration; `.github/workflows/security.yml`
for the scanners). `jest.config.js` selects a tier directory via the
`JEST_TIER` env var, set by the npm scripts:

- `npm run test:unit` — logic + CDK fine-grained assertions + fast-tier cdk-nag
  assertion + fast-check properties (no emulator/Docker). The script passes
  `--coverage`, so every run also collects Istanbul coverage into
  `reports/coverage/` (`lcov` + `json-summary` + text) and enforces the **100%
  `coverageThreshold` gate** (see "Coverage reporting pipeline" below).
- `npm run test:integ-snapshot` — `@aws-cdk/integ-runner` synth-only snapshot
  diff against `integ/*.js.snapshot/` (no emulator). Runs in the **unit
  job** after `npm run build`. Refresh baselines with
  `npm run test:integ-snapshot:update` against MiniStack (see
  [`CONTRIBUTING.md`](../CONTRIBUTING.md)).
- `npm run test:integration` — AWS SDK v3 against deployed MiniStack resources.
- `npm run test:mutation` — Stryker over the scoped logic (zero-surviving-mutants gate).
- `npm run test:fuzz-regression` — replays the committed `fuzz/corpus/` seed
  inputs through the handler as plain Jest tests (own config,
  `jest.fuzz.config.js`), asserting the same invariants as the exploratory
  fuzzer; emits `reports/junit/fuzz.xml`. This runs in the **PR-gating unit
  job**, so a crash input pinned into the corpus becomes a permanent regression
  test that fails the tier. It uses jazzer's `FuzzedDataProvider` to decode
  corpus bytes but the **plain Jest runner** (not `@jazzer.js/jest-runner`,
  which is incompatible with Jest 30 — issue #126), so it needs no native
  libFuzzer addon and runs on any host.
- `npm run fuzz` — jazzer.js libFuzzer target (exploratory scheduled job, not a
  fast gate; generates new inputs, needs GLIBC ≥ 2.38).
- `npm run test:e2e` — runs the `describe.skip` placeholder (no real-account
  stage yet).

Mutation testing covers the pure input→output logic: `lambda/index.js` and the
helper-script logic modules (see "Helper-script tier" below). The CDK stack is
declarative config Stryker can't tie to synth output, so the infra is covered
by cdk-nag/checkov, fine-grained CDK `Template` assertions, and the
`@aws-cdk/integ-runner` snapshot baseline instead.

> **Two senses of "snapshot."** The infra snapshot here is the **`@aws-cdk/integ-runner`
> cloud-assembly baseline** — committed under `integ/*.js.snapshot/`, compared
> on every PR via synth-only `npm run test:integ-snapshot`. It is **not** the old
> Jest `toMatchSnapshot` baseline (removed in #66). This is distinct from the
> [`@aws-cdk/integ-tests-alpha` `IntegTest`](https://github.com/aws-samples/aws-cdk-examples/blob/main/SNAPSHOT_TESTING.md)
> **deploy-and-assert** workflow (`--update-on-failed`), which we use only when
> refreshing the baseline against MiniStack. That deploy style is still **not** a
> real-account E2E dimension (currently TBD).

## Helper-script tier (`.github/scripts/` + `scripts/`)

The CI/security helper scripts are **first-class citizens of the same
coverage + mutation + fuzz gates** as the application code (issue #165). Before
that change they were `.mjs` files that either had a `*.test.mjs` **nothing ever ran**
(jest globs `test/**/*.test.ts`; no workflow invoked `node --test`) or no test
at all — a false green on security-critical transformers (a wrong ClamAV/Sonar
SARIF silently resolves Code-Scanning alerts; a wrong `license-verdict` closes
or escalates a `review:license` issue).

**Layout — one pair per script:**

- `<name>.ts` — the **tested logic module** (the pure transformer/decider).
  Imported **in-process** by unit specs (`test/unit/<name>.test.ts`) and by the
  fuzz-regression tier, so it flows through the 100% coverage gate (#124) and
  Stryker (#122) with **zero new tooling**.
- `<name>.mjs` — a **thin CLI shim** (argv/read/write/exit only) that
  `import`s the `.ts`. **Node 24 strips the types on import** (stable,
  unflagged), so the workflows keep calling `node .github/scripts/<name>.mjs …`
  with **no build step and no path change** (`security.yml`,
  `license-review-poller.yml`). The shim is not gate-collectable in-process and
  is excluded by the `**/*.ts`-only globs.

Gated modules today: `clamav-to-sarif.ts`, `sonar-to-sarif.ts`,
`license-verdict.ts` (`.github/scripts/`), and `ministack-upstream.ts`
(`scripts/`, pure logic only — its network `gh search` / registry I/O stays in
the `.mjs` shim, uncollectable in-process by the same convention that excludes
`services/**/checks.*.ts`).

**Path convention — future scripts inherit the gates automatically:**

- `jest.config.js` `collectCoverageFrom` includes `.github/scripts/**/*.ts` and
  `scripts/**/*.ts` (100% gate).
- `jest.config.js` `moduleFileExtensions` puts `ts` **before** `mjs`/`js` so an
  extension-less import resolves to the `.ts` logic module (never the sibling
  `.mjs` CLI shim), which is also what makes Stryker mutate the file jest
  actually loads.
- `stryker.config.mjs` `mutate:` lists the four modules; the maintainer bar for
  #165 is **0 surviving mutants** (`break: 100`). The handful of genuinely
  **equivalent** mutants (e.g. a caught-then-discarded `throw` message, a
  regex anchor made redundant by a downstream re-validation, a defensive
  `?? []` fallback) are marked with an inline `// Stryker disable next-line
<mutator>: <reason>` — each justified, never a blanket ignore.
- `tsconfig.json` **excludes** these `.ts` from the emitting build (so no
  compiled `.js` shadows the source); `tsconfig.scripts.json` (`noEmit`)
  type-checks them and is run by `npm run build`.
- `jest.fuzz.config.js` uses `ts-jest` so the SARIF/`license-verdict`
  fuzz-regression targets can import the `.ts` in-process, with corpora under
  `fuzz/corpus-clamav/`, `fuzz/corpus-sonar/`, `fuzz/corpus-license/` — seeded
  with the adversarial cases (filenames containing `": "`/`FOUND`, empty,
  garbage/binary, very-long, and the REAL `Eicar-Test-Signature FOUND` line —
  never the live EICAR byte-string on a scanned path).
- `.github/workflows/ci.yml` path-filter lists `.github/scripts/**`,
  `scripts/**`, and `tsconfig.scripts.json` so a change to any of them runs the
  unit / mutation / fuzz jobs.

Adding a new logic-bearing helper is therefore: drop a `<name>.ts` + a
`test/unit/<name>.test.ts`, keep any CLI in a `<name>.mjs` shim — and it is
gated with no further config edits.

## Coverage reporting pipeline

Test reporting is split between a **gate** (Jest) and a **reporter** (octocov)
— deliberately, so the enforcement threshold has exactly one home (issues #124
and #125, parent #122):

- **Collection + gate (phase 1, #124):** `npm run test:unit` passes
  `--coverage`; `jest.config.js` writes `reports/coverage/` (`lcov.info`,
  `coverage-summary.json`, text table) and enforces
  `coverageThreshold: 100%` on branches/functions/lines/statements — the test
  step itself fails if any scoped file drops below 100%. Coverage is switched
  on by the npm script, NOT `collectCoverage: true` in the config, so
  Stryker's per-mutant Jest runs stay coverage-free (see the config comments).
  The integration tier collects no coverage — its code executes inside
  MiniStack's Lambda container, where Istanbul can't instrument it.
- **Reporting (phase 2, #125):** the SHA-pinned
  [`k1LoW/octocov-action`](https://github.com/k1LoW/octocov-action) step in
  `ci.yml`'s unit job feeds `reports/coverage/lcov.info` to
  [octocov](https://github.com/k1LoW/octocov) (both MIT), configured by
  `.octocov.yml`:
  - **One sticky PR comment** (`comment.if: is_pull_request`,
    `updatePrevious: true`) — updated in place on each push, never spammed.
  - **Job step summary** always (`summary.if: true`) — the fork-PR fallback,
    since a fork's read-only token can't comment (octocov skips the comment
    gracefully; summaries need no write permission).
  - **Delta vs `main`** via the `artifact://` datastore: default-branch runs
    (`report.if: is_default_branch`) store the baseline report as an Actions
    artifact (`octocov-report`); PR runs `diff:` against it. No SaaS vendor,
    no extra secret.
  - **No `coverage.acceptable:`** — octocov reports, never gates; the 100%
    threshold lives in Jest only.
- **Step summaries (phase 1, #124):** the unit, integration, and mutation jobs
  each append test counts (and the coverage/mutation tables) to
  `GITHUB_STEP_SUMMARY` with `if: always()`, so the run's summary page shows
  results even on failure.

All report files live under the gitignored `reports/` tree and are uploaded as
artifacts with `if: always()` (the produce → always-upload → enforce
convention).

### Polyglot reporting contract

The reporting layer is language-agnostic by construction — jest-junit emits
the cross-language JUnit XML schema, octocov reads LCOV/Cobertura/Clover/
SimpleCov/JaCoCo/Go natively, and Stryker's JSON conforms to the
mutation-testing-report-schema. **Any new language tier added to this repo
(e.g. the planned jmeter-java-dsl Java tier, #73) MUST plug into the same
report tree rather than inventing its own:**

| Report            | Where               | Format                                                                                |
| ----------------- | ------------------- | ------------------------------------------------------------------------------------- |
| Test results      | `reports/junit/`    | JUnit XML (one file per tier: `unit.xml`, `integration.xml`, `fuzz.xml`)              |
| Coverage          | `reports/coverage/` | **LCOV preferred**; JaCoCo/Cobertura/Clover/SimpleCov XML acceptable (octocov-native) |
| Mutation (if any) | `reports/mutation/` | mutation-testing-report-schema JSON                                                   |

New coverage files are wired in by appending to `coverage.paths:` in
`.octocov.yml` — the sticky comment, summary, and delta then aggregate across
languages with no new tooling.

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
