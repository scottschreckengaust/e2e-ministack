# Security Tooling

Canonical reference for the repo's security/supply-chain gates: what each gate
does, the **license policy** and its rationale, and the **intentional**
local (pre-commit) ↔ remote (CI) coverage gap. Registered as a source-of-truth
doc for the drift audit (#76); CLAUDE.md points here rather than duplicating it.

## Gate inventory

Two workflows. `ci.yml` (changes → unit → integration) builds, lint/unit-tests
with the cdk-nag synth gate, then deploys/tests against MiniStack. `security.yml`
runs the scanners below (also on a weekly cron). Every gate follows the
**produce → always-upload → enforce** pattern so its report artifact exists even
when the job fails; SARIF-capable gates also upload to the Security tab.

| Gate                  | Workflow     | Scope                                   | Failure policy |
| --------------------- | ------------ | --------------------------------------- | -------------- |
| CodeQL (JS/TS)        | security.yml | SAST over source                        | hard-fail      |
| Semgrep               | security.yml | SAST over source                        | hard-fail      |
| npm audit             | security.yml | npm advisories (`--audit-level=high`)   | hard-fail      |
| OSV-Scanner           | security.yml | lockfile advisories                     | hard-fail      |
| Grype (FS)            | security.yml | filesystem vuln scan                    | hard-fail      |
| Grype (MiniStack img) | security.yml | third-party emulator image by digest    | report-only    |
| **dependency-review** | security.yml | PR dep-diff: vulns + **license policy** | hard-fail (PR) |
| **SBOM (Syft)**       | security.yml | CycloneDX SBOM of the tree              | informational  |
| Gitleaks              | security.yml | secrets (full history)                  | hard-fail      |
| checkov + cfn-lint    | security.yml | synthesized CloudFormation              | hard-fail      |
| Threat model          | security.yml | `threat-model.tc.json` parses/sections  | hard-fail      |
| actionlint + zizmor   | security.yml | workflow correctness + security         | hard-fail      |

## License policy — DENY-list (and why, not allow-list)

The PR-time `dependency-review` gate enforces a **deny-list** of disallowed
licenses (`deny-licenses`), not an allow-list. This was a deliberate, verified
choice:

- `actions/dependency-review-action` **does not fail closed on undetectable
  licenses** in either mode — per its docs, _"if we can't detect the license for
  a dependency we will inform you, but the action won't fail."_ So an
  allow-list's headline advantage (block-the-unknown) **does not materialise**
  here; unknowns pass in both modes.
- A **deny-list directly expresses the governance goal** — keep
  copyleft / network-copyleft / source-available-non-FOSS dependencies out (the
  same line that rejected k6/AGPL in #73 and removed Renovate/AGPL). The denied
  set is small and stable.
- An **allow-list would be high-friction**: every new permissive SPDX id a
  dependency ships (`0BSD`, `BlueOak-1.0.0`, `Python-2.0`, `Unlicense`, …) would
  false-positive until the list is widened.

### License-family taxonomy (the rationale, by family)

| Family                      | Examples                                        | Verdict            |
| --------------------------- | ----------------------------------------------- | ------------------ |
| Permissive                  | MIT, Apache-2.0, BSD-2/3, ISC, 0BSD             | ✅ allow           |
| Weak / file-level copyleft  | LGPL-\*, MPL-2.0, EPL-1.0/2.0                   | ❌ deny¹           |
| Strong copyleft             | GPL-2.0, GPL-3.0                                | ❌ deny            |
| Network copyleft            | AGPL-3.0                                        | ❌ deny (#73 line) |
| Source-available / non-FOSS | SSPL-1.0, BUSL-1.1, Elastic-2.0, Commons-Clause | ❌ deny            |

¹ **LGPL/MPL/EPL are absent from the current tree** (verified with
`license-checker`), so denying them is free today and keeps the gate
fail-closed against a future introduction. Loosen only if a needed dependency
forces it.

### Enforced `deny-licenses`

See `security.yml` → `dependency-review` job. Includes the deprecated bare
`GPL-2.0`/`GPL-3.0` ids alongside the SPDX `-only`/`-or-later` forms because
some tools still emit the bare ids.

### Known limitations (documented, not hidden)

- **Undetected/unlicensed dependencies pass `dependency-review` silently** (see
  above). **Trivy's license scan is the intended full-tree backstop** for the
  `UNKNOWN` case (separate follow-up, tracked under #77).
- **Dual licenses such as `(MIT OR GPL-3.0-or-later)` stay GREEN** — the SPDX
  `OR` expression is satisfied by the permissive side, so a `GPL-*` deny does
  not (and should not) flag them. `case@1.6.3` in the current tree is exactly
  this case; it is not a violation.
- **Riders such as `Commons-Clause`** (e.g. `MIT AND Commons-Clause`) are only
  best-effort under SPDX-expression matching; Trivy's license scan is the
  authoritative catch.

### Severity threshold

`dependency-review` uses `fail-on-severity: high`, aligned with
`npm audit --audit-level=high`. The action default is `low`. To triage the full
backlog during a rollout, temporarily lower it to `low` (emit-all), then ratchet
back to `high`.

## SBOM

Syft generates a **CycloneDX** SBOM (`sbom.cdx.json`), uploaded as a workflow
artifact. It is **informational** (no enforce step). Artifact-only for now;
attaching to releases is deferred until a release process exists. The SBOM can
also feed Grype/Trivy for consistent component coverage.

## Intentional local ↔ remote (pre-commit) gap

Per CLAUDE.md, pre-commit is a **fast convenience tier**, not a mirror of CI —
the slow/heavy gates stay CI-only **by design**. So a clean `git push` does not
fully predict green CI. This gap is **known and deliberate**, not accidental:

**Run in pre-commit AND CI:** hygiene hooks, gitleaks, actionlint, eslint, tsc,
markdownlint, prettier.

**Intentionally CI-only** (too slow / needs network / needs synth or the
emulator): CodeQL, Grype, zizmor, the full cdk-nag synth gate, checkov,
cfn-lint, npm audit, OSV-Scanner, dependency-review (needs the PR dep-diff),
SBOM, and the MiniStack E2E deploy/integration tier.

Closing the _cheap, high-signal_ subset of this gap (a Semgrep pre-commit hook
matching CI, OSV-Scanner locally) is tracked separately — Semgrep parity under
**#79**, the rest under **#77**'s parent scope.

## Pinning

All scanner tools are pinned (action SHA / binary checksum / pinned version) per
[PINNING.md](PINNING.md). The two actions added for the supply-chain work
(`dependency-review-action` v5.0.0, `sbom-action` v0.24.0) are SHA-pinned like
every other `uses:` and are registered as future targets of the #78 pin-sync
updater.
