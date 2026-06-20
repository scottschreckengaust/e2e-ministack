# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`e2e-ministack` — a minimal **AWS CDK (TypeScript) app exercised by end-to-end integration tests against [MiniStack](https://github.com/ministackorg/ministack)**, a free local AWS emulator (LocalStack alternative, port 4566). A trivial stack (two S3 buckets + a Node.js Lambda) is deployed into MiniStack with `cdk deploy`, then Jest tests invoke the deployed resources through the AWS SDK. The whole loop runs locally and in CI with no real AWS account.

## Commands

Node is pinned to 24 via `mise.toml` (`mise install` to set up). MiniStack must be running before bootstrap/deploy/test.

```bash
# 1. Start MiniStack (see "Why these flags" below — all are required for
#    Lambda/RDS/ECS to work):
docker run -d --name ministack --network host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e LAMBDA_EXECUTOR=docker -e MINISTACK_RDS_PUBLIC_ENDPOINT=1 -e MINISTACK_HOST=localhost \
  ministackorg/ministack:full@sha256:c5ce466eb2e73b5f3af86a5a1aea780c1e8fcf8f04ec0e2042a5cf759d6dcdd3

# 2. Point the AWS toolchain at MiniStack (BOTH endpoint vars are required):
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ENDPOINT_URL_S3=http://localhost:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=us-east-1

npm ci                 # install (use `npm install` when changing deps)
npm run build          # tsc compile
npm run bootstrap      # cdk bootstrap aws://000000000000/us-east-1
npm run deploy         # cdk deploy --require-approval never
npm run test:unit      # fast: Lambda logic + CDK fine-grained assertions + cdk-nag (no emulator)
npm test               # alias for test:unit
npm run test:integration  # jest AWS-SDK tests against deployed MiniStack resources
npm run test:e2e       # placeholder for a real-account stage (currently skipped)
npm run test:mutation  # Stryker mutation testing of the Lambda logic (gate: >=80%)
npm run fuzz           # jazzer.js coverage-guided fuzzing (needs GLIBC >= 2.38)
npm run destroy        # cdk destroy --force

# Reset MiniStack state between runs (faster than restarting the container):
curl -X POST http://localhost:4566/_ministack/reset

# Run a single test (set the tier so jest looks in the right dir):
JEST_TIER=integration npx jest -t "invokes the deployed Lambda"
```

CI runs this same sequence — see `.github/workflows/ci.yml`.

## Architecture / layout

- `bin/app.ts` — CDK entrypoint; instantiates the stack with the fixed account/region from `lib/env.ts` (`MINISTACK_ENV` = `000000000000`/`us-east-1`) so the bootstrap environment matches locally and in CI. The env is pinned **unconditionally** — it does _not_ read `CDK_DEFAULT_ACCOUNT`/`CDK_DEFAULT_REGION`, because the CDK CLI populates those from the ambient credential chain and a contributor with live AWS creds would otherwise synth/deploy against their real account (issue #2). `lib/env.ts` is the single source of truth, imported by both `bin/app.ts` and the unit tests so the literal can't drift.
- `lib/ministack-stack.ts` — the stack: two S3 buckets (data bucket `cdk-demo-bucket` + access-log bucket `cdk-demo-log-bucket`) + Lambda `cdk-doubler`. The **log bucket** exists solely to receive the data bucket's S3 server access logs — it satisfies the access-logging security rules (cdk-nag `AwsSolutions-S1` / checkov `CKV_AWS_18`) and logs to itself to avoid an infinite chain of log buckets; only the data bucket is exercised by tests. **Resource names are hard-coded** so tests address them directly without reading CloudFormation outputs (`test/unit/stack.test.ts` asserts exactly two buckets).
- `lambda/index.js` — the function under test (doubles `event.n`, returns `process.version`). `lambda/index.d.ts` is a hand-written type contract (committed) so the unit test can import it with types without `allowJs`.
- **Test pyramid** (`jest.config.js` picks the tier dir via `JEST_TIER`):
  - `test/unit/` — `lambda.test.ts` (pure handler logic) + `stack.test.ts` (CDK `Template` fine-grained assertions **plus** a fast-tier cdk-nag `AwsSolutions` assertion). Synth-only; no emulator/Docker. The fine-grained assertions encode security/structural intent ("blocks public access", "denies insecure transport", DLQ/CMK, etc.); the cdk-nag assertion drives the same `AwsSolutionsChecks` pack `bin/app.ts` registers — via the pack's documented `validateScope(stack)` testing entry point — and asserts zero unsuppressed findings, so a nag regression fails in the fast tier rather than only in CI `cdk synth`. **The full-template snapshot was removed (issue #25):** it overlapped the fine-grained assertions, couldn't guard the cdk-nag posture, and its incremental signal was dominated by Lambda asset-hash churn (constant `-u` re-baselining that trains reviewers to rubber-stamp). Note cdk-nag v3 removed the v2 Aspects `visit` API and `Annotations.fromStack` no longer surfaces nag findings, and an in-process `app.synth()` does not enforce the v3 policy-validation plugin — hence `validateScope`.
  - `test/integration/` — Jest + AWS SDK v3 clients pointed at `AWS_ENDPOINT_URL`, against deployed MiniStack resources. Assumes `cdk deploy` already ran.
  - `test/e2e/` — placeholder (`describe.skip`) for a future real-account deployment stage.
- **Mutation testing** — `npm run test:mutation` (Stryker) mutates `lambda/index.js` against the unit tier; CI gate breaks under 80% (currently 100%). Scoped to the Lambda logic only — the CDK stack is declarative config Stryker can't tie to synth output (mutants show as "no coverage"), so it's covered by cdk-nag/checkov/fine-grained assertions instead. `incremental: true` caches per-mutant verdicts; CI restores/saves that cache via `actions/cache`.
- **Fuzzing** — `fuzz/handler.fuzz.js` is a jazzer.js (libFuzzer) target asserting the handler never throws and never returns a non-finite `doubled`. fast-check property tests live in the unit tier (always-on gate); jazzer is a separate, time-boxed `fuzz` job that runs on schedule/`workflow_dispatch` only (fuzzing is exploratory, not a fast gate) and needs **GLIBC >= 2.38** (fine on `ubuntu-latest`; won't run on older hosts). The corpus is cached across runs; crash inputs upload as an artifact.
  - **The fast-check seed is pinned** (`test/setup.fast-check.ts`, wired via Jest `setupFilesAfterEnv`). Without it `@fast-check/jest` seeds each run with `Date.now()^Math.random()`, so the same commit explores different inputs every run — which made the property gate (and Stryker's initial dry run, which _is_ the unit tier) flaky: identical code passed on one CI trigger and failed on another. Pinning makes every run reproducible; unbounded random exploration still happens in the scheduled jazzer job. Known bug classes are locked by explicit `it.each` cases, not luck. **Don't unpin to "find more bugs" — add a fuzz iteration or an example case instead.**

## Why these flags / non-obvious constraints

These were established by running the stack, not from docs alone — don't "simplify" them away:

- **MiniStack runs as a `docker run` step, NOT a GitHub Actions `services:` container.** Lambda/ECS/RDS/ElastiCache work by MiniStack spawning _sibling_ containers via the host Docker socket. A `services:` container can mount the socket but cannot join the host network, so RDS readiness probes hit the wrong loopback and the DB hangs in `creating` forever.
- **`--network host`** is what makes sibling containers reachable: MiniStack's loopback becomes the host, so the host-published ports of RDS/etc. (and `MINISTACK_RDS_PUBLIC_ENDPOINT=1`'s reported `localhost:PORT`) actually resolve. Linux-only — fine on `ubuntu-latest`.
- **`-v /var/run/docker.sock` + `LAMBDA_EXECUTOR=docker`** — required for real Lambda/RDS/ECS containers.
- **Health check: do NOT pass `--health-cmd`.** The image ships its own python-based `HEALTHCHECK` (it has no `curl`/`wget`). A `curl`-based override goes `unhealthy` (exit 127) and blocks the job. Poll `docker inspect -f '{{.State.Health.Status}}'` instead.
- **Both `AWS_ENDPOINT_URL` and `AWS_ENDPOINT_URL_S3` must be set** for `cdk`. The modern bare CDK CLI (>= 2.1000) honors `AWS_ENDPOINT_URL` natively (no `cdklocal` wrapper needed), but it _requires_ the S3-specific var too because S3 virtual-host addressing can't be inferred from the generic endpoint. Omitting it throws "If specifying 'AWS_ENDPOINT_URL' then 'AWS_ENDPOINT_URL_S3' must be specified".
- **No `autoDeleteObjects: true` on buckets** — that synthesizes a custom-resource Lambda that doesn't complete cleanly against the emulator and stalls the deploy. Clean up with `cdk destroy` / `_ministack/reset` instead.

## Version coupling

- `aws-cdk-lib` is pinned to **2.260.0**. Note `lambda.Runtime.NODEJS_24_X` requires >= 2.230.0 (2.220.0 and earlier lack it), so don't downgrade below that.
- `aws-cdk` (CLI) is **2.1128.0**. Post-2.179 the CLI versions diverged from the library (CLI is numbered `2.10xx.x`/`2.11xx.x`), so they are pinned independently and are not expected to match.
- **Everything pinnable is pinned** — Actions (SHA), Node (exact patch), the MiniStack image (digest), CodeQL bundle, and the pip/uvx scanner versions. See [docs/PINNING.md](docs/PINNING.md) for the full inventory and what's intentionally left floating (and why). Use `npm ci` (never `npm install`) in CI so the lockfile governs.

## Security checks

Two workflows. `ci.yml` (jobs: changes → unit → integration) lints, runs unit tests + the cdk-nag synth gate, then deploys/tests against MiniStack. `security.yml` runs the scanners (also on a weekly cron).

**Observability convention (both workflows):** every gate writes a report file (SARIF / JUnit / HTML / text) and uploads it with `if: always()` so it's downloadable from the run's Artifacts even on failure. Hard-fail tools use the **produce → always-upload → enforce** pattern: run the tool with `set +e`, save its exit code to a `*.outcome` file, upload the report, then a final `if: always()` step `source`s the outcome and fails the job. This guarantees the diagnostic artifact exists precisely when the job fails. SARIF-capable scanners (Semgrep, checkov, Grype, OSV; CodeQL natively) also `upload-sarif` to the **Security tab**. Report/SARIF/outcome files are gitignored and prettier/markdownlint-ignored.

- **cdk-nag (AwsSolutions)** — runs _inside_ `cdk synth` (wired in `bin/app.ts` via `Validations.of(app).addPlugins(...)`, the v3 API — NOT the v2 `Aspects` API). Any unsuppressed finding fails synth. The stack is hardened to pass cleanly. Suppressions use CDK-native `Validations.of(construct).acknowledge({ id, reason })` — but note cdk-nag v3 **removed `NagSuppressions`**, and granular rule IDs containing `::` (e.g. `IAM5[Resource::arn:<AWS::Partition>:...]`) **cannot be acknowledged** (CDK reserves `::`), so such findings must be fixed structurally, not suppressed.
- **ESLint** (`npm run lint`) — flat config, typescript-eslint.
- **checkov + cfn-lint** — scan synthesized `cdk.out` templates. checkov hard-fails (43 pass / 0 fail / 1 skip). `CKV_AWS_117` (Lambda-in-VPC) is skipped via CloudFormation `Metadata` (`checkov: { skip: [...] }`) injected with `cfnFn.addMetadata(...)` — the only way to suppress on CDK-generated templates. cfn-lint's two `W` warnings (`AccessControl` legacy prop, redundant dependency) are expected and not failed on.
- **Dependency/supply-chain** — `npm audit --audit-level=high`, OSV-Scanner (lockfile), Grype (filesystem).
- **SAST/secrets** — Semgrep (`--config=auto --error`), Gitleaks (full history), CodeQL (JS/TS).
- **zizmor** — audits the workflow files themselves. To keep it clean: pin every action to a **commit SHA** (not a tag), set top-level `permissions: contents: read`, and `persist-credentials: false` on every checkout.
- **actionlint** — runs in `security.yml` alongside zizmor. Validates workflow _correctness_ (schema, shellcheck on `run:` blocks) — complements zizmor's _security_ audit. Both workflow-file linters live together there.
- **Threat model** — `threat-model.tc.json` is an [AWS threat-composer](https://github.com/awslabs/threat-composer) artifact (design-time, hand-authored). Edit it in the threat-composer web app or the AWS Toolkit VS Code extension (see [docs/THREAT-MODELING.md](docs/THREAT-MODELING.md)). CI only checks it parses and has the expected sections — threat-composer has no credential-free CI generator (its AI generator needs a real Bedrock account), so this is a human-maintained artifact, not an automated finding source.

### Not used here (would need a real AWS account)

cdk-nag/checkov are _shift-left_ (analyze the template). **ScoutSuite** and **Prowler** are _runtime CSPM_ — they audit a deployed account's live config (real IAM trust, actual public buckets, account settings) via cloud APIs, which a template can't reveal. This repo has no real-account stage (only MiniStack), and neither tool works meaningfully against the emulator, so they're intentionally omitted. Add them as a CSPM gate if/when a real AWS account is introduced.

## Pre-commit hooks

Fast local tier mirroring a subset of CI (`.pre-commit-config.yaml`). One-time setup:

```bash
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

- Hooks: standard hygiene (large files, merge conflicts, shebang/executable consistency, EOF/whitespace, `check-json`/`check-yaml`, private-key + AWS-credential detection), **gitleaks** (secrets), **actionlint** (workflows), and `local` **eslint** + **tsc** that reuse the repo's pinned `node_modules` (so the hook and CI run identical tooling).
- `tsconfig.json` is excluded from `check-json` (it's JSONC — has comments).
- **`bin/app.ts` is mode `100755`** (executable) on purpose — it has a `#!/usr/bin/env node` shebang, so the shebang/executable hooks require it. Don't `chmod -x` it.
- gitleaks/actionlint build from Go source on first install. This works out of the box for most. **Only** if your network can't reach `proxy.golang.org` (e.g. a TLS-intercepting corporate proxy) is a workaround needed: run `go env -w GOPROXY=direct` once (persists in Go's env config across shells), then reinstall the hooks.
- This is a convenience tier, not an enforcing control (`--no-verify` bypasses it; absent until `pre-commit install`). CI remains the source of truth; the slow gates (cdk-nag synth, checkov, CodeQL, grype, MiniStack E2E) stay in CI only.

## Dependency notes

- `package.json` defines **three** `overrides`, each forcing a transitive dependency up to a patched version. All are docs-only safety floors enforced by the lockfile (`npm ci`), and `npm audit --audit-level=high` reports 0 vulnerabilities. Don't accept `npm audit fix`'s suggestion to downgrade `ts-jest`. Re-derive the consumer lists below with `npm ls js-yaml markdown-it qs` if they drift.
  - **`js-yaml ^4.2.0`** — the Jest/Istanbul coverage toolchain pulls `js-yaml@^3` transitively, which carries a moderate DoS (GHSA-h67p-54hq-rp68). v4 is safe here because both consumers call `js-yaml.load()`, which still exists in v4 (only `safeLoad` was removed). Two consumers resolve to `js-yaml@4.2.0`: `markdownlint-cli2` (direct) and `@istanbuljs/load-nyc-config` (via `ts-jest → @jest/transform → babel-plugin-istanbul`).
  - **`markdown-it ^14.2.0`** — pulled by `markdownlint-cli2`. Forces past older `markdown-it` advisories (ReDoS/uncontrolled-resource-consumption in `<14`). `markdownlint-cli2` is compatible with v14, so the bump is transparent.
  - **`qs ^6.15.2`** — pulled by `@stryker-mutator/core → typed-rest-client`. Forces past the prototype-pollution class of `qs` advisories; `typed-rest-client` only uses `qs.stringify`, which is API-stable across the bump.
- The GitHub-side Dependabot "npm_and_yarn … js-yaml" updates fail because the fix lives in this override, not a direct-dep bump; that's expected, not a CI regression.

## Repository conventions

- `.remember/` is local session/memory tooling, not project code — ignore it when reasoning about the application.
