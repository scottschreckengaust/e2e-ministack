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
npm run test:unit          # fast: Lambda logic + CDK assertions/snapshot (NO emulator)
npm test                   # alias for test:unit
npm run test:integration   # AWS SDK tests against deployed MiniStack resources
npm run test:mutation      # Stryker mutation testing of the Lambda logic (gate: >=80%)
```

- **Unit** tests are synth-only — no Docker or emulator required, so they're
  the fastest feedback loop.
- **Integration** tests assume `cdk deploy` has already run against MiniStack
  (`npm run bootstrap` → `npm run deploy` first).

Run a single test by setting the tier so Jest looks in the right directory:

```bash
JEST_TIER=integration npx jest -t "invokes the deployed Lambda"
```

## Regenerating the CDK snapshot

`test/unit/stack.test.ts` includes a **full-template snapshot** (baseline in
`test/unit/__snapshots__/`). If you make an intended change to the stack, the
snapshot will go stale and the unit tier will fail until you regenerate it:

```bash
npm run test:unit -- -u
```

Review the snapshot diff before committing — it's your confirmation that the
template changed exactly as you expected, and nothing else.

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
4. `npm run test:unit` — and if you changed the stack, regenerate the snapshot
   (see above) and commit it.
5. If you touched the integration path, run the MiniStack loop locally
   (`bootstrap` → `deploy` → `test:integration`).

CI runs the same sequence — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

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

## Questions

Open an issue if anything is unclear or you hit a snag setting up — improving
this guide is itself a welcome contribution.
