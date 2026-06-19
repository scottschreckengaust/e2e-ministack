# Dependency Pinning

This repo pins every version it reasonably can, for reproducible builds and
supply-chain safety. This file is the authoritative inventory.

## Pinned

| What                          | Where                                | Pin form                                 |
| ----------------------------- | ------------------------------------ | ---------------------------------------- |
| GitHub Actions (all `uses:`)  | `.github/workflows/*.yml`            | commit SHA (`# vX` comment)              |
| npm dependencies (transitive) | `package-lock.json` + `npm ci`       | exact, lockfile-resolved                 |
| `aws-cdk`, `aws-cdk-lib`      | `package.json`                       | exact (`2.1128.0`, `2.260.0`)            |
| Node.js                       | `mise.toml`, workflow `node-version` | exact patch (`24.17.0`)                  |
| npm (via Corepack)            | `package.json` (`packageManager`)    | exact (`npm@11.13.0`)                    |
| MiniStack image               | `ci.yml`                             | digest (`@sha256:c5ce466…`)              |
| CodeQL analyzer bundle        | `security.yml` (`tools:`)            | `codeql-bundle-v2.25.6`                  |
| Semgrep                       | `security.yml`                       | `==1.167.0`                              |
| cfn-lint / checkov            | `security.yml`                       | `==1.51.5` / `==3.3.0`                   |
| OSV-Scanner                   | `security.yml`                       | `v2.4.0` **+ SHA-256 verify**            |
| actionlint                    | `security.yml`, pre-commit           | `v1.7.12` (install script self-verifies) |
| gitleaks, pre-commit-hooks    | `.pre-commit-config.yaml`            | `rev:` tags                              |
| threat-composer-ai (uvx)      | `.mcp.json`                          | git commit SHA                           |
| Prettier, markdownlint-cli2   | `package.json` + lockfile            | exact, lockfile-resolved                 |
| Stryker (mutation testing)    | `package.json` + lockfile            | exact, lockfile-resolved                 |
| fast-check, jazzer.js (fuzz)  | `package.json` + lockfile            | exact, lockfile-resolved                 |

> **Scope of "exact" above.** Only `aws-cdk` and `aws-cdk-lib` are pinned to a
> bare exact version _string_ in `package.json`. The other direct runtime deps
> — `@aws-sdk/client-lambda` and `@aws-sdk/client-s3` (`^3.x`) and `constructs`
> (`^10.x`) — and all direct devDependencies use **caret ranges**. Their
> _installed_ versions are still pinned, but by the lockfile, not the manifest
> (see "npm `^`/`~` ranges" below). So the install is reproducible; the
> `package.json` declaration is a compatibility floor, not the source of truth.

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

No automation yet (update strategy TBD — Renovate or manual). To refresh a pin
by hand: bump the version/SHA/digest in the file above, re-run the relevant
gate locally to confirm, and commit. For digests:
`docker buildx imagetools inspect ministackorg/ministack:full` shows the
current manifest digest; for Action SHAs, `git ls-remote <repo> refs/tags/<tag>`.
