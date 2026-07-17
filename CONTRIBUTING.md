# Contributing to e2e-ministack

Thanks for your interest in contributing! This is a small project — a minimal
AWS CDK (TypeScript) app exercised by end-to-end integration tests against
[MiniStack](https://github.com/ministackorg/ministack), a free local AWS
emulator. This guide covers everything you need to get set up, run the checks
locally, and open a PR that passes CI on the first try.

> This file is for humans. `CLAUDE.md` holds the same conventions plus deeper
> rationale for AI assistants — if anything here is ambiguous, that's the
> fuller reference.

## Development setup

### Node

Node is pinned to **24** (exact patch) via [`mise.toml`](mise.toml). With
[mise](https://mise.jdx.dev) installed:

```bash
mise install   # reads mise.toml and installs the pinned Node
```

### Install dependencies

Always use `npm ci` (never `npm install`) so the lockfile governs the exact
dependency versions — this is what CI does, and it keeps your tree identical to
everyone else's:

```bash
npm ci
```

Use `npm install` **only** when you are deliberately changing dependencies.

### MiniStack (for integration tests)

The unit tier needs nothing, but the integration tier deploys into a running
MiniStack. The README's [Quickstart](README.md#-quickstart) has the exact
`docker run` command and the AWS environment variables to export — those flags
are non-obvious and load-bearing, so copy them verbatim.

## Running the checks

This repo follows a test pyramid; `JEST_TIER` selects the tier:

```bash
npm run build              # tsc compile
npm run lint               # ESLint (flat config, typescript-eslint)
npm run test:unit          # fast: Lambda logic + CDK fine-grained assertions (NO emulator)
npm run test:integ-snapshot  # @aws-cdk/integ-runner snapshot diff (synth-only; NO emulator)
npm test                   # alias for test:unit
npm run test:integration   # AWS SDK tests against deployed MiniStack resources
npm run test:mutation      # Stryker mutation testing of the scoped logic (gate: 0 surviving mutants)
```

- **Unit** tests are synth-only — no Docker or emulator required, so they're
  the fastest feedback loop.
- **Integration** tests assume `cdk deploy` has already run against MiniStack
  (`npm run bootstrap` → `npm run deploy` first).

Run a single test by setting the tier so Jest looks in the right directory:

```bash
JEST_TIER=integration npx jest -t "invokes the deployed Lambda"
```

## Regenerating the CDK integ snapshot

`integ/integ.ministack-stack.ts` is an **`@aws-cdk/integ-tests-alpha`**
integration test exercised by **`@aws-cdk/integ-runner`**. The committed baseline
lives in `integ/integ.ministack-stack.js.snapshot/`.

**PR gate (synth-only):** after `npm run build`, run:

```bash
npm run test:integ-snapshot
```

No MiniStack required — this only synths and diffs against the baseline.

**After an intentional stack change**, refresh the baseline against a running
MiniStack (same env vars as `cdk deploy` — see README Quickstart). Reset emulator
state first if you already deployed the demo stack (`curl -X POST
http://localhost:4566/_ministack/reset`):

```bash
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_ENDPOINT_URL_S3=http://localhost:4566 \
  AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test \
  AWS_REGION=us-east-1 AWS_DEFAULT_REGION=us-east-1 \
  CDK_DEFAULT_ACCOUNT=000000000000 CDK_DEFAULT_REGION=us-east-1

npm run bootstrap   # once per fresh MiniStack
npm run test:integ-snapshot:update
```

Review the snapshot diff before committing — it is your confirmation that the
cloud assembly changed exactly as you expected, and nothing else.

## Pre-commit hooks

A fast local tier mirrors a subset of CI. It's a convenience (not an enforcing
control — CI remains the source of truth), but installing it catches most
problems before they reach a PR. One-time setup:

```bash
pip install pre-commit   # or: brew install pre-commit
pre-commit install
```

The hooks cover standard hygiene, secret detection (gitleaks), workflow linting
(actionlint), and local `eslint` + `tsc` that reuse the repo's pinned
`node_modules`.

> **GOPROXY workaround:** gitleaks and actionlint build from Go source on first
> install. This works out of the box for most people. **Only** if your network
> can't reach `proxy.golang.org` (e.g. a TLS-intercepting corporate proxy), run
> `go env -w GOPROXY=direct` once (it persists across shells), then reinstall
> the hooks.

## Before you open a PR

Run the local gates that mirror CI so you don't bounce off a red build:

1. `npm ci` (clean install from the lockfile)
2. `npm run build`
3. `npm run lint`
4. `npm run test:unit` and `npm run test:integ-snapshot` — and if you changed the
   stack, regenerate the integ snapshot (see above) and commit the updated
   `integ/*.js.snapshot/` tree.
5. If you touched the integration path, run the MiniStack loop locally
   (`bootstrap` → `deploy` → `test:integration`).

CI runs the same sequence — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Stacked PRs (recommended: git-town)

Large changes are easier to review as a **stack** of small, dependent PRs than
as one big branch. This is a per-developer workflow choice — it touches no CI or
repo config — so you're free to use whatever you like, but the recommendation
here is [**git-town**](https://www.git-town.com/).

- **Why git-town:** it is **MIT-licensed**, a **CLI-only** tool (no SaaS
  account, no third-party push access, no data egress), and git-native — it
  drives ordinary branches and works with GitHub's normal PR/merge UI, so there
  are no synthetic branches to lock you in. It's actively maintained and has
  first-class support for stacked changes.
- **Alternative:** [**spr**](https://github.com/ejoffe/spr) (also MIT, CLI-only)
  is a clean choice if you prefer a one-commit-per-PR model.
- **Rejected:** [Graphite](https://graphite.dev) was evaluated and **rejected**.
  It is a proprietary, single-vendor SaaS that requires third-party push access
  and data egress — the same single-vendor / lock-in concern that governs tool
  and Action adoption in this repo (see `AGENTS.md` § Security checks; the same
  line that rejected k6 and removed Renovate).

Neither git-town nor spr is installed or wired into CI — this is a workflow
recommendation, not an adopted dependency. Install git-town per its
[docs](https://www.git-town.com/install) and a typical stacked flow looks like:

```bash
git town sync                 # pull main and rebase your stack onto it
git town append feat-part-1   # start the first branch in the stack
# ...commit work...
git town append feat-part-2   # stack the next branch on top of the previous
git town propose              # open a PR for the current branch
git town sync                 # keep the whole stack rebased as review progresses
```

Each branch in the stack becomes its own PR; merge them bottom-up through the
normal GitHub UI. Revisit this recommendation if GitHub's native stacked-PR
feature (currently private preview) reaches general availability for this repo.

## How CI reports results (good to know)

Both workflows follow an **observability convention**: every gate writes a
report file (SARIF / JUnit / HTML / text) and uploads it as a run artifact even
on failure (`if: always()`). So when a check fails, download its artifact from
the run's **Artifacts** section to see exactly what went wrong — the diagnostic
is guaranteed to be there precisely when the job fails. SARIF-capable scanners
also surface findings in the repository's **Security** tab.

A defense-in-depth set of security gates (cdk-nag, ESLint, checkov, cfn-lint,
npm audit, OSV-Scanner, Grype, Semgrep, CodeQL, Gitleaks, zizmor, actionlint)
runs in [`security.yml`](.github/workflows/security.yml); see the README's
[Security checks](README.md#-security-checks) table for the full layout.

## Versions are pinned on purpose

Almost everything pinnable is pinned — Actions (by commit SHA), Node (exact
patch), the MiniStack image (by digest), and scanner versions. See
[docs/PINNING.md](docs/PINNING.md) for the full inventory and what's
intentionally left floating. Please keep new dependencies and Actions pinned to
match.

## Releases & the changelog (automated)

Commit messages follow **Conventional Commits** (`feat:`, `fix:`, `chore:`, …).
You do **not** edit `CHANGELOG.md` by hand. On every push to `main`,
[`release.yml`](.github/workflows/release.yml) runs
[release-please](https://github.com/googleapis/release-please) (Apache-2.0,
GitHub-maintained), which reads the conventional-commit history and keeps an
open **release PR** up to date — computing the next SemVer bump and regenerating
the changelog. Merging that release PR is what cuts a tagged GitHub Release; no
release happens until a maintainer merges it. Config lives in
`release-please-config.json` + `.release-please-manifest.json`.

## Questions

Open an issue if anything is unclear or you hit a snag setting up — improving
this guide is itself a welcome contribution.
