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
| MiniStack image               | `ci.yml`                             | digest (`@sha256:c5ce466…`)              |
| CodeQL analyzer bundle        | `security.yml` (`tools:`)            | `codeql-bundle-v2.25.6`                  |
| Semgrep                       | `security.yml`                       | `==1.167.0`                              |
| cfn-lint / checkov            | `security.yml`                       | `==1.51.5` / `==3.3.0`                   |
| OSV-Scanner                   | `security.yml`                       | `v2.4.0` **+ SHA-256 verify**            |
| actionlint                    | `security.yml`, pre-commit           | `v1.7.12` (install script self-verifies) |
| gitleaks, pre-commit-hooks    | `.pre-commit-config.yaml`            | `rev:` tags                              |
| threat-composer-ai (uvx)      | `.mcp.json`                          | git commit SHA                           |
| Prettier, markdownlint-cli2   | `package.json` + lockfile            | exact, lockfile-resolved                 |

## Intentionally NOT pinned (with reasons)

- **npm `^`/`~` ranges in `package.json`** — these are resolution _floors_
  only. `npm ci` installs exactly what `package-lock.json` says, so the actual
  install is pinned. The ranges document intended compatibility; the lockfile
  is the source of truth. (Run `npm ci`, never `npm install`, in CI.)
- **`uv` / `uvx` / `pipx` / `pip` runners themselves** — provided by the local
  environment / GitHub runner image. Their _outputs_ are pinned (the package
  versions above); the launchers are not. Pin via a `setup-uv`/`setup-python`
  action with a fixed version if you need launcher reproducibility too.
- **`ubuntu-latest` runner image** — GitHub-managed; floats by design. Pin to
  `ubuntu-24.04` if you need the OS image fixed.
- **Homebrew tool versions (local dev only)** — `pre-commit`, scanners
  installed via brew on a developer machine are not repo-pinned; CI is the
  reproducible source of truth.

## Updating a pin

No automation yet (update strategy TBD — Renovate or manual). To refresh a pin
by hand: bump the version/SHA/digest in the file above, re-run the relevant
gate locally to confirm, and commit. For digests:
`docker buildx imagetools inspect ministackorg/ministack:full` shows the
current manifest digest; for Action SHAs, `git ls-remote <repo> refs/tags/<tag>`.
