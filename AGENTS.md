# AGENTS.md

This file is the source of truth for working with this repository — for any coding agent (and for humans). It captures the project, build, test, security, and pinning knowledge for the repo. Tool-specific entrypoints (e.g. `CLAUDE.md`) only point here.

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
  ministackorg/ministack:full@sha256:dd2cf4d2e58a9ee6534a52f1edf06a720064c24b90ca28d42b1c57181b9b8815

# 2. Point the AWS toolchain at MiniStack (BOTH endpoint vars are required):
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ENDPOINT_URL_S3=http://localhost:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=us-east-1

npm ci                 # install (use `npm install` when changing deps)
npm run build          # tsc compile
npm run bootstrap      # cdk bootstrap aws://000000000000/us-east-1
npm run deploy         # cdk deploy --require-approval never
npm run test:unit      # fast: Lambda logic + CDK fine-grained assertions + cdk-nag (no emulator); collects coverage (gate: 100%)
npm test               # alias for test:unit
npm run test:integration  # jest AWS-SDK tests against deployed MiniStack resources
npm run test:e2e       # placeholder for a real-account stage (currently skipped)
npm run test:mutation  # Stryker mutation testing of the Lambda logic (gate: >=80%)
npm run test:fuzz-regression  # PR-gating: replays committed fuzz/corpus/ seeds as Jest tests -> reports/junit/fuzz.xml
npm run fuzz           # exploratory jazzer.js fuzzing, scheduled only (needs GLIBC >= 2.38)
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
- **Test strategy** — tiers (`jest.config.js` picks the tier dir via `JEST_TIER`): `test/unit/` (synth-only handler logic + CDK `Template` fine-grained assertions, a full-template `toMatchSnapshot` baseline in `test/unit/__snapshots__/` updated with `-u`, and a fast-tier cdk-nag `AwsSolutions` assertion via `validateScope`), `test/integration/` (AWS SDK v3 against deployed MiniStack resources, assumes `cdk deploy` ran), `test/e2e/` (`describe.skip` real-account placeholder). The full strategy — reframed as a parallel quality **matrix** (functional / performance / security / acceptance / mobile) with per-dimension status — lives in **[docs/TESTING.md](docs/TESTING.md)**, the single source of truth.
- **Coverage + reporting** — `test:unit` passes `--coverage`: Jest writes `reports/junit/unit.xml` (jest-junit) and `reports/coverage/` (`lcov.info` + `coverage-summary.json`) and enforces a **100% `coverageThreshold` gate** (the gate lives in Jest, #124). The unit job also runs the fuzz-regression tier (`reports/junit/fuzz.xml`) and uploads it like `unit.xml`. In CI, **octocov** (`.octocov.yml`, SHA-pinned `k1LoW/octocov-action` in the unit job — both MIT, license-checked per the tool-adoption line below) posts ONE sticky PR coverage comment with the delta vs `main` (baseline stored via the `artifact://` datastore on default-branch runs) and writes the job summary; **octocov reports, never gates** — no `coverage.acceptable:`. **Polyglot contract:** a new language tier emits JUnit XML to `reports/junit/` + coverage (LCOV preferred; JaCoCo/Cobertura/Clover/SimpleCov acceptable) to `reports/coverage/`, then joins `coverage.paths:` in `.octocov.yml`. Details in [docs/TESTING.md](docs/TESTING.md) § Coverage reporting pipeline.
- **Mutation testing** — `npm run test:mutation` (Stryker) mutates `lambda/index.js` against the unit tier; CI gate breaks under 80% (currently 100%). Scoped to the Lambda logic only — the CDK stack is declarative config Stryker can't tie to synth output (mutants show as "no coverage"), so it's covered by cdk-nag/checkov/fine-grained assertions instead. `incremental: true` caches per-mutant verdicts; CI restores/saves that cache via `actions/cache`.
- **Fuzzing** — two jazzer.js targets, split by mode:
  - **Regression (PR-gating):** `fuzz/handler.regression.test.js` (`npm run test:fuzz-regression`, own config `jest.fuzz.config.js`) replays the **committed** seed corpus (`fuzz/corpus/`) through the handler as ordinary Jest tests — same invariants (never throws; 200⇒finite `doubled`; clean 400) — and emits `reports/junit/fuzz.xml` (one `<testcase>` per input). It runs in the **unit job** (the PR gate), so a crash input pinned into `fuzz/corpus/` becomes a permanent regression test that fails the tier. It uses jazzer's `FuzzedDataProvider` (imported from `@jazzer.js/core/dist/FuzzedDataProvider`, the addon-free path) to decode corpus bytes but the **plain Jest runner** — deliberately NOT `@jazzer.js/jest-runner`, which reaches into Jest's private `Runtime._scriptTransformer` that **Jest 30 removed** (repo pins `jest@^30`), so no native libFuzzer addon and no GLIBC floor (#126, phase 3 of #122).
  - **Exploratory (scheduled):** `fuzz/handler.fuzz.js` is the standalone jazzer.js (libFuzzer) target that GENERATES new inputs. It runs as a separate, time-boxed `fuzz` job on schedule/`workflow_dispatch` only (fuzzing is exploratory, not a fast gate) and needs **GLIBC >= 2.38** (fine on `ubuntu-latest`; won't run on older hosts). Its corpus is cached across runs; crash inputs upload as an artifact — decode one and drop it into `fuzz/corpus/` to pin it in the regression tier.
  - fast-check property tests live in the unit tier (always-on gate).
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

Two main workflows. `ci.yml` (jobs: changes → unit → integration) lints, runs unit tests + the cdk-nag synth gate, then deploys/tests against MiniStack. `security.yml` runs the scanners (also on a weekly cron). A small scheduled third, `license-review-poller.yml`, resolves open `license-review` issues against ClearlyDefined weekly — auto-closing on an allow-list-satisfiable declared license, escalating (and going red on an unacceptable one) otherwise (#127 Leg B; see docs/SECURITY-TOOLING.md).

**Observability convention (both workflows):** every gate writes a report file (SARIF / JUnit / HTML / text) and uploads it with `if: always()` so it's downloadable from the run's Artifacts even on failure. Hard-fail tools use the **produce → always-upload → enforce** pattern: run the tool with `set +e`, save its exit code to a `*.outcome` file, upload the report, then a final `if: always()` step `source`s the outcome and fails the job. This guarantees the diagnostic artifact exists precisely when the job fails. SARIF-capable scanners (Semgrep, checkov, Grype, OSV; CodeQL natively) also `upload-sarif` to the **Security tab**. Report/SARIF/outcome files are gitignored and prettier/markdownlint-ignored.

- **cdk-nag (AwsSolutions)** — runs _inside_ `cdk synth` (wired in `bin/app.ts` via `Validations.of(app).addPlugins(...)`, the v3 API — NOT the v2 `Aspects` API). Any unsuppressed finding fails synth. The stack is hardened to pass cleanly. Suppressions use CDK-native `Validations.of(construct).acknowledge({ id, reason })` — but note cdk-nag v3 **removed `NagSuppressions`**, and granular rule IDs containing `::` (e.g. `IAM5[Resource::arn:<AWS::Partition>:...]`) **cannot be acknowledged** (CDK reserves `::`), so such findings must be fixed structurally, not suppressed.
- **ESLint** (`npm run lint`) — flat config, typescript-eslint.
- **checkov + cfn-lint** — scan synthesized `cdk.out` templates. checkov hard-fails (43 pass / 0 fail / 1 skip). `CKV_AWS_117` (Lambda-in-VPC) is skipped via CloudFormation `Metadata` (`checkov: { skip: [...] }`) injected with `cfnFn.addMetadata(...)` — the only way to suppress on CDK-generated templates. cfn-lint's two `W` warnings (`AccessControl` legacy prop, redundant dependency) are expected and not failed on.
- **Dependency/supply-chain** — `npm audit --audit-level=high`, OSV-Scanner (lockfile), Grype (filesystem), `dependency-review-action` (PR-time dep-diff: vulns + an **allow-list license policy** — only the permissive licenses present in the tree pass, so copyleft/AGPL/non-FOSS introductions fail by omission; `fail-on-severity: high`), and Syft (CycloneDX SBOM artifact, informational). Full posture, the license-allow rationale (why allow-list not deny-list — `deny-licenses` is deprecated upstream), and the intentional pre-commit↔CI gap live in **[docs/SECURITY-TOOLING.md](docs/SECURITY-TOOLING.md)** (the single source of truth). The same license line governs **adopting new tools and GitHub Actions** (their licenses aren't packages in the lockfile, so the CI dependency gate never sees them): AGPL/copyleft is a near-dealbreaker and single-vendor lock-in is avoided — the stance that rejected k6 for load testing (#73) and removed Renovate (PR #54 → #80). Check a candidate tool's license against this line before wiring it in.
- **SAST/secrets** — Semgrep (`--config=auto --error`), Gitleaks (full history), CodeQL (JS/TS).
- **zizmor** — audits the workflow files themselves. To keep it clean: pin every action to a **commit SHA** (not a tag), set top-level `permissions: contents: read`, and `persist-credentials: false` on every checkout.
- **actionlint** — runs in `security.yml` alongside zizmor. Validates workflow _correctness_ (schema, shellcheck on `run:` blocks) — complements zizmor's _security_ audit. Both workflow-file linters live together there.
- **shellcheck** — gates **standalone** `*.sh`/`*.bash` scripts (the `shellcheck` job in `ci.yml`, path-gated on shell changes; mirrored by a pre-commit hook). This is distinct from actionlint, which only shellchecks `run:` blocks _inside_ workflow YAML and never sees standalone scripts. CI pins **shellcheck `v0.11.0`** (tarball + SHA-256 verify, _not_ the floating `ubuntu-latest` copy) to match the pre-commit `shellcheck-py` pin, so the two flag identically — a coupled pre-commit↔CI pin tracked in [docs/PINNING.md](docs/PINNING.md). shellcheck (GPLv3) is invoked as an external linter — not linked or redistributed — so it adds no copyleft dependency.
- **Threat model** — `threat-model.tc.json` is an [AWS threat-composer](https://github.com/awslabs/threat-composer) artifact (design-time, hand-authored). Edit it in the threat-composer web app or the AWS Toolkit VS Code extension (see [docs/THREAT-MODELING.md](docs/THREAT-MODELING.md)). CI only checks it parses and has the expected sections — threat-composer has no credential-free CI generator (its AI generator needs a real Bedrock account), so this is a human-maintained artifact, not an automated finding source.

### Not used here (would need a real AWS account)

cdk-nag/checkov are _shift-left_ (analyze the template). **ScoutSuite** and **Prowler** are _runtime CSPM_ — they audit a deployed account's live config (real IAM trust, actual public buckets, account settings) via cloud APIs, which a template can't reveal. This repo has no real-account stage (only MiniStack), and neither tool works meaningfully against the emulator, so they're intentionally omitted. Add them as a CSPM gate if/when a real AWS account is introduced.

## Pre-commit hooks

Fast local tier mirroring a subset of CI (`.pre-commit-config.yaml`). One-time setup:

```bash
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

- Hooks: standard hygiene (large files, merge conflicts, shebang/executable consistency, EOF/whitespace, `check-json`/`check-yaml`, private-key + AWS-credential detection), **gitleaks** (secrets), **actionlint** (workflows), **shellcheck** (standalone `*.sh` scripts, via `shellcheck-py`), and `local` **eslint** + **tsc** + **markdownlint** + **prettier** that reuse the repo's pinned `node_modules` (so the hook and CI run identical tooling).
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
- **`.github/scanner-requirements/overrides.txt`** is the pip analog of the npm `overrides`: it forces `aiohttp==3.14.1` past checkov's declared `<3.14.0` cap (the sub-3.14.1 releases carry the advisories behind Dependabot alerts #14–#24). Because the pinned closure now violates checkov's metadata, `security.yml` installs it with `pip install --require-hashes --no-deps` (the lockfile is a complete closure, so install-time resolution is redundant). Regenerate `iac.txt` with the command in its header; drop the override once checkov allows `aiohttp>=3.14.1`. The GitHub-side Dependabot "pip … aiohttp" update jobs fail for the same reason as the npm ones above — the fix lives in the override + recompile, which Dependabot can't author.

## Repository conventions

- `.remember/` is local session/memory tooling, not project code — ignore it when reasoning about the application. Likewise `.claude/` holds Claude Code's local configuration (settings, hooks, skills, worktrees) — tooling, not application code.
- **Isolate feature/issue work in a git worktree** — don't mutate the primary checkout for multi-step changes. The canonical, vendor-neutral location is **`.worktrees/<branch>`** at the repo root (gitignored). Any agent or human creates one with plain git — `git worktree add .worktrees/<branch> -b <branch>` (or check out an existing branch into it) — then rebases onto `main` before opening a PR. All agents target this same path so everyone converges on it. (Claude Code's native worktree tool defaults to `.claude/worktrees/` instead — also gitignored — and its base path isn't settings-configurable; see CLAUDE.md. `.worktrees/` is the convention to standardize on.)
- **Agent-agnostic tooling** — shared skills and the `.agents/` layout are documented in [`.agents/README.md`](.agents/README.md). Skills under `.agents/skills/` are auto-discovered by Cursor (and other Agent Skills–compatible tools); project instructions stay in this `AGENTS.md`.
- **MCP / agent config** — the repo ships Model Context Protocol configs so an agent can drive the project and GitHub repo. `.mcp.json` is Claude Code's path; **Cursor reads `.cursor/mcp.json`** (different interpolation syntax — see [docs/MCP.md](docs/MCP.md#cursor-ide)). There is no `CURSOR.md`; Cursor auto-loads this `AGENTS.md`. Other agents use their own paths (documented in MCP.md).
- **Docs drift audit** — the recurring "Repo Revisit" process re-checks the docs/governance prose against the actual code/config; see [docs/REPO-REVISIT.md](docs/REPO-REVISIT.md) (run it via the [`repo-revisit`](.agents/skills/repo-revisit/SKILL.md) skill).
