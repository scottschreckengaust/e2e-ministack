# Dependency Pinning

This repo pins every version it reasonably can, for reproducible builds and
supply-chain safety. This file is the authoritative inventory.

## Pinned

| What                                                   | Where                                | Pin form                                                                        |
| ------------------------------------------------------ | ------------------------------------ | ------------------------------------------------------------------------------- |
| GitHub Actions (all `uses:`)                           | `.github/workflows/*.yml`            | commit SHA (`# vX` comment)                                                     |
| npm dependencies (transitive)                          | `package-lock.json` + `npm ci`       | exact, lockfile-resolved                                                        |
| `aws-cdk`, `aws-cdk-lib`                               | `package.json`                       | exact (`2.1128.0`, `2.260.0`)                                                   |
| Node.js                                                | `mise.toml`, workflow `node-version` | exact patch (`24.17.0`)                                                         |
| npm (via Corepack)                                     | `package.json` (`packageManager`)    | exact (`npm@11.13.0`)                                                           |
| MiniStack image                                        | `ci.yml`                             | digest (`@sha256:636c4ef5…`)                                                    |
| ClamAV image                                           | `security.yml` (`clamav` service)    | digest (`@sha256:6f4a9e7d…`); **signature DB floats** (freshclam)               |
| SonarQube image                                        | `security.yml` (`sonarqube` service) | digest (`@sha256:160bd2f6…`)                                                    |
| SonarSource actions                                    | `security.yml`                       | commit SHA (`sonarqube-scan-action` v8.2.0, `-quality-gate-action` v1.2.0)      |
| CodeQL analyzer bundle                                 | `security.yml` (`tools:`)            | `codeql-bundle-v2.25.6`                                                         |
| Semgrep                                                | `security.yml`                       | `==1.167.0`                                                                     |
| cfn-lint / checkov                                     | `security.yml`                       | `==1.52.0` / `==3.3.2`                                                          |
| OSV-Scanner                                            | `security.yml`                       | `v2.4.0` **+ SHA-256 verify**                                                   |
| Grype (`anchore/scan-action`)                          | `security.yml`                       | action SHA + engine `grype-version:`; vuln **DB floats** (#183)                 |
| Trivy (`trivy-action`)                                 | `security.yml`                       | action SHA + engine `version:`; vuln **DB floats**, cached (#183)               |
| actionlint                                             | `security.yml`, pre-commit           | `v1.7.12` (install script self-verifies)                                        |
| shellcheck                                             | `ci.yml`, pre-commit                 | `v0.11.0` **+ SHA-256 verify** (CI) / `shellcheck-py v0.11.0.1` (hook)          |
| gitleaks, pre-commit-hooks                             | `.pre-commit-config.yaml`            | `rev:` tags                                                                     |
| threat-composer-ai (uvx)                               | `.mcp.json`, `.cursor/mcp.json`      | git commit SHA (same pin in both; `npm run check:mcp-parity`)                   |
| Prettier, markdownlint-cli2                            | `package.json` + lockfile            | exact, lockfile-resolved                                                        |
| Stryker (mutation testing)                             | `package.json` + lockfile            | exact, lockfile-resolved                                                        |
| fast-check, jazzer.js (fuzz)                           | `package.json` + lockfile            | exact, lockfile-resolved                                                        |
| `@aws-cdk/integ-runner` / `@aws-cdk/integ-tests-alpha` | `package.json` + lockfile            | exact (`2.202.1` / `2.260.0-alpha.0`; runner line independent of `aws-cdk-lib`) |

> **Scope of "exact" above.** Only `aws-cdk` and `aws-cdk-lib` are pinned to a
> bare exact version _string_ in `package.json`. The other direct runtime deps
> — `@aws-sdk/client-lambda` and `@aws-sdk/client-s3` (`^3.x`) and `constructs`
> (`^10.x`) — and all direct devDependencies use **caret ranges**. Their
> _installed_ versions are still pinned, but by the lockfile, not the manifest
> (see "npm `^`/`~` ranges" below). So the install is reproducible; the
> `package.json` declaration is a compatibility floor, not the source of truth.
>
> **Scanner pin closures + overrides.** The Semgrep and cfn-lint/checkov pins
> above are the _top-level_ versions; the full hash-verified closures live in
> `.github/scanner-requirements/{semgrep,iac}/requirements.txt` (regeneration
> commands in each file's header). They sit in per-tool subdirs named
> `requirements.txt` so the SCA scanners (grype/trivy/OSV) recognize them by
> filename — the old flat `{semgrep,iac,overrides}.txt` names were invisible to
> those tools (#226). `iac/requirements.txt` additionally carries a resolution
> override — `.github/scanner-requirements/overrides/requirements.txt` forces
> `aiohttp==3.14.1` past checkov's `<3.14.0` cap (security fix; Dependabot alerts
> #14–#24) — so `security.yml` installs it with `--no-deps` (see AGENTS.md
> "Dependency notes"). Drop the override when checkov's cap allows
> `aiohttp>=3.14.1`.

## Intentionally NOT pinned (with reasons)

- **npm `^`/`~` ranges in `package.json`** — these are resolution _floors_
  only (this covers the caret-ranged direct deps noted above —
  `@aws-sdk/client-*`, `constructs` — as well as all transitive deps). `npm ci`
  installs exactly what `package-lock.json` says, so the actual
  install is pinned. The ranges document intended compatibility; the lockfile
  is the source of truth. (Run `npm ci`, never `npm install`, in CI.) Note this
  is about the dependency _ranges_, not npm itself — the npm **tool** is now
  pinned via `packageManager` (Corepack) + an `engines.node` guardrail (see the
  Pinned table). Activating it in CI (`corepack enable` in the setup-node steps)
  is a recommended follow-up.
- **`uv` / `uvx` / `pipx` / `pip` runners themselves** — provided by the local
  environment / GitHub runner image. Their _outputs_ are pinned (the package
  versions above); the launchers are not. Pin via a `setup-uv`/`setup-python`
  action with a fixed version if you need launcher reproducibility too.
- **Trivy vulnerability database** (and, symmetrically, **Grype's DB**) — for
  both scanners **two layers are now pinned and one floats by design** (#183):
  the _action_ is SHA-pinned AND the scanner _engine_ is version-pinned
  (`trivy-action` `version:`, `anchore/scan-action` `grype-version:`) — the
  action SHA alone left the engine floating to "latest at runtime", which made
  local↔CI (and run↔run) findings diverge. Only the **vuln DB floats**: a stale
  CVE feed would defeat the point of a vuln scanner, so the DB must track
  upstream disclosures. (Engine pins are input _string values_, which Dependabot
  cannot bump — refresh them manually as part of the #76 drift audit; they are
  #78 pin-sync targets.) To
  keep runs fast despite the float, the DB is **cached across runs** with
  `actions/cache` (rolling `github.run_id` key, mirroring the mutation/fuzz
  caches in `ci.yml`), so each run refreshes rather than re-downloads from cold.
  Note (#84): because the DB floats and the `ministack-image` / `trivy-image`
  jobs are now **hard-fail** (VEX-gated), a newly-disclosed high+ CVE on the
  pinned image can turn CI red **without any repo change** — that is the intended
  signal, resolved by VEX-accepting it under `.vex/` (or bumping the digest once
  MiniStack ships a fix). The weekly `security.yml` cron surfaces such drift even
  absent a push.
- **ClamAV virus signature database** — the `clamav/clamav` image is pinned by
  digest, but its signature CVDs are refreshed by `freshclam` at container start
  (floating by design, same rationale as the Trivy/Grype vuln DBs above): pinning
  signatures would defeat the scan's purpose of catching newly-catalogued
  malware. The `clamav`/`sonarqube` service images and the two SonarSource
  actions are all SHA/digest-pinned (see the Pinned table) and are #78 pin-sync
  targets like every other `uses:`/image.
- **`ubuntu-latest` runner image** — GitHub-managed; floats by design. Pin to
  `ubuntu-24.04` if you need the OS image fixed.
- **Homebrew tool versions (local dev only)** — `pre-commit`, scanners
  installed via brew on a developer machine are not repo-pinned; CI is the
  reproducible source of truth.

## Known-deprecated transitive packages

`npm ci` prints a few `npm warn deprecated` lines for packages pulled in deep
in the dev toolchain. They are **transitive** (no direct dependency on them),
buried under tools we _do_ pin, and carry no open advisory that `npm audit
--audit-level=high` flags — so they're tolerated, not bumped:

- **`glob@7.x` / `glob@10.x`** and **`inflight@1.0.6`** — deprecated as
  unmaintained (and `inflight` leaks memory). They arrive via the Jest /
  test-tooling chain. We can't bump them without forking upstream; an `override`
  would risk breaking those tools for no security gain.

These warnings are expected and not a CI regression. Revisit if any of them
graduates to a real advisory (then add a scoped `override`, as we do for
`js-yaml` / `markdown-it` / `qs` — see CLAUDE.md "Dependency notes").

## Updating a pin

**Renovate is intentionally not used** (it is AGPL-3.0; this project avoids AGPL
tooling — the same governance constraint that ruled out k6 for load testing).
**Dependabot updates GitHub Actions only** (`.github/dependabot.yml`, weekly,
grouped, 7-day cooldown, #221) — it rewrites each `uses:` action SHA to the
latest release. It is deliberately **NOT** pointed at npm/pip: those closures are
hand-curated (lockfile + `overrides` + `--require-hashes`) and coupled to
pre-commit, so a bot would fight the curated pins (its js-yaml/aiohttp jobs
already fail — see AGENTS.md dependency notes). The rest of the pins (pipx `==`,
OSV version+SHA, the MiniStack image digest, the coupled Semgrep binary+ruleset,
the mise↔workflow Node version) still need the repo-owned "pin-sync" process
planned in #78. Refresh those by hand: bump the version/SHA/digest in the file
above, re-run the relevant gate locally to confirm, and commit. For digests:
`docker buildx imagetools inspect ministackorg/ministack:full` shows the
current manifest digest; for Action SHAs, `git ls-remote <repo> refs/tags/<tag>`.

### `mise run update:ministack` — the MiniStack digest fan-out (#152)

The MiniStack image digest is duplicated across several pin sites, so a manual
bump is easy to get partially wrong (workflows on a new digest, docs on the old
one — split-brain). `mise run update:ministack` automates it as **repo-owned
scripting** (no AGPL tooling): it resolves the current multi-arch OCI **index**
digest of `ministackorg/ministack:full` and fans it out from the single source
of truth (`services/_registry/ministack-pin.json`) to every pin site, then
self-verifies with the #212 drift guard.

```bash
mise run update:ministack             # resolve + fan out + self-verify
mise run update:ministack -- --dry-run  # report the diff only; write nothing
mise run update                       # umbrella: runs every update:* task
```

- **What it rewrites** — exactly the site set the drift guard
  (`.github/scripts/check-ministack-digest-drift.sh`) checks: the registry
  `.digest` field, the three workflows (`ci.yml`, `security.yml` ×2,
  `ministack-compat.yml`), and the two docs (`AGENTS.md`, `README.md`). It
  substitutes the **literal** full `sha256:<64hex>` pin, so the truncated prose
  form (`636c4ef5…`) is left untouched.
- **What it deliberately leaves alone** — `services/_registry/provisioning.json`'s
  `lastVerifiedDigest` is a _semantic_ record (a bump invalidates the compat
  catalog), so it is not blindly rewritten; update it via the compat re-verify
  flow. The `.vex/` set likewise needs a manual reconcile per `.vex/README.md`
  after a real bump.
- **Index digest, not per-arch** — CI runs amd64 and dev machines are arm64, so
  the pin must be the platform-agnostic OCI _index_ digest
  (`docker buildx imagetools inspect … --format '{{json .Manifest.Digest}}'`),
  not a per-arch manifest digest.
- **Structure** — pure fan-out logic lives in `scripts/update-ministack.ts`
  (jest-gated, 100% coverage); the docker/network resolution + file writes +
  guard run live in the un-gated `scripts/update-ministack.mjs` shim (the same
  `.ts`+`.mjs` split as `ministack-upstream.*`). Because `docker buildx` isn't
  available in the unit CI job, the task is exercised by humans / a scheduled
  workflow. This is the ergonomics surface of the #78 pin-sync updater;
  `update:node` / `update:actions` / `update:scanners` compose into `update`
  the same way as they land.

### Drift audit (2026-06, issue #83)

A toolchain-drift audit (issue #83) checked every pin above against its upstream
latest release. PR #86 bumped the safe, independent subset (`actions/cache` v6,
`zizmor-action` v0.5.7, cfn-lint 1.52.0, checkov 3.3.2). A follow-up re-audit
found **no further independently-actionable drift**: every pinned Action and
scanner above is at its current latest release. (The CodeQL `v4` action tag has
since advanced past the previously-pinned commit; #154 repinned all 7
`github/codeql-action/*` refs to the current release's peeled SHA
`99df26d…` with an exact `# v4.37.0` comment, closing the zizmor
`ref-version-mismatch` alerts.) The only residual is
**Semgrep**, which is intentionally _not_ bumped in isolation — its binary
version is coupled to the pre-commit rev and the vendored ruleset (tracked in
issue #79). The coupled pre-commit↔CI pairs (gitleaks, actionlint, OSV-Scanner,
shellcheck) are already in lockstep at their latest. With no safe standalone bump left, #83
is effectively folded into the planned pin-sync work (#78) and the Semgrep
triplet (#79); refresh those coupled groups together when they land.
