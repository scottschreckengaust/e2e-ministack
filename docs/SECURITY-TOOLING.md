# Security Tooling

Canonical reference for the repo's security/supply-chain gates: what each gate
does, the **license policy** and its rationale, and the **intentional**
local (pre-commit) ↔ remote (CI) coverage gap. Registered as a source-of-truth
doc for the drift audit (#76); CLAUDE.md points here rather than duplicating it.

## Gate inventory

Two workflows. `ci.yml` (changes → unit → integration) builds, lint/unit-tests
with the cdk-nag synth gate, then deploys/tests against MiniStack. `security.yml`
runs the scanners below (also on a weekly cron). A third, small scheduled
workflow — `license-review-poller.yml` — resolves open `license-review` issues
against ClearlyDefined weekly (see "Could not detect a license" below). Every
gate follows the **produce → always-upload → enforce** pattern so its report
artifact exists even when the job fails; SARIF-capable gates also upload to the
Security tab.

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

## Remediating a scanner finding — fix it properly, don't suppress it

When a SAST / code-scanning gate (Semgrep, CodeQL, …) flags code, the standard
is a **real, proven fix**. A suppression (`nosemgrep` / inline-ignore /
alert-dismissal) clears the _gate_ but leaves the code-scanning _alert_ open, and
a prose "it's a false positive" note asserts safety instead of enforcing it —
the weak form. Fixes must **stick and be actually done, not hacked**. The
procedure, in order of preference:

1. **Read the scanner's own source / rule definition — don't guess what clears
   it.** A finding is only understood once you've read the rule. For Semgrep,
   fetch the rule YAML from
   [`semgrep/semgrep-rules`](https://github.com/semgrep/semgrep-rules) and read
   its `pattern-sanitizers`; for CodeQL, the query's sources/sinks/sanitizers.
   The recognized sanitizer shapes are specific and often surprising — e.g. the
   `path-join-resolve-traversal` rule accepts `.replace(...)`, `.indexOf(...)`,
   or a function whose **name matches `sanitize`** on the value entering the
   sink, while `path.basename()` alone and a `resolve()`+`startsWith()`
   containment check do **not** clear it. Reproduce locally with the **pinned**
   scanner version (read it from the repo's scanner config — e.g.
   `pip install --require-hashes -r .github/scanner-requirements/semgrep.txt`,
   or `uvx semgrep==<pin>`) so your local verdict matches CI exactly.

2. **Prefer a vetted, time-tested fixer over bespoke code.** Do **not**
   roll-your-own for a problem an industry-standard, exercised primitive already
   solves — reach first for: the platform/standard-library primitive (e.g.
   `path.win32.basename`/`path.posix.basename`, `URL`, `crypto.timingSafeEqual`),
   then a **widely-used, actively-maintained, formally-verified-or-heavily-
   exercised** library snippet or OWASP/language-community reference
   implementation. Bespoke security code is a liability: it lacks the years of
   adversarial exercise a vetted implementation has. **This is subject to the
   license policy below** — an adopted fixer library / snippet is a dependency
   (and a _tool-adoption governance decision_, § tool-adoption line): it must be
   license-acceptable (permissive; no AGPL/copyleft) and SHA/version-pinned like
   any other. If the only vetted option has an unacceptable license, escalate —
   don't silently vendor it.

   **Bespoke is justified only when** no vetted primitive fits the _exact_ sink
   semantics. Judge by behavior, not familiarity: e.g. a **reject**-invalid guard
   is correct where a **mutating** sanitizer (`sanitize-filename`-style
   char-stripping) would silently act on a _different_ resource than intended —
   there, minimal format-validation against a documented allow-pattern is the
   right call, not a library. Record _why_ bespoke was chosen in a comment.

3. **Prove the fix with an adversarial corpus from an authoritative source.**
   Add executable tests whose attack payloads come from a recognized catalogue —
   [OWASP](https://owasp.org) attack pages (e.g. Path Traversal), CWE examples,
   the language community's known-bad vectors — asserting the guard **rejects**
   the attacks and **accepts** legitimate inputs. Reproduce the scanner locally
   → **0 findings**; confirm existing behavior still passes. Prove-don't-assert
   catches real bugs (a first-cut path guard here let `a\b` through on POSIX —
   the OWASP-derived test caught it before merge).

4. **Scope honestly.** Defend only the layer the sink sits at, and say so:
   a filesystem-name guard need not — and must not pretend to — handle
   URL-percent-encoded forms (`%2e%2e%2f`, overlong-UTF-8 `%c0%af`) if nothing
   URL-decodes the value first; asserting those as "caught" misrepresents the
   guard. Document out-of-scope forms rather than faking coverage.

Suppression is a **last resort** for a genuinely unfixable true-false-positive,
and only with explicit maintainer sign-off recorded on the PR — never
self-approved. (The same _inline-scoped_ vs _global `--exclude-rule`_ distinction
tracked for the vendored ruleset in #79 applies when suppression is unavoidable.)

## License policy — ALLOW-list (and why, not deny-list)

The PR-time `dependency-review` gate enforces an **allow-list** of permitted
licenses (`allow-licenses`), not a deny-list. This reverses an earlier
deny-list decision for two reasons:

- **`deny-licenses` is deprecated and slated for removal**
  ([upstream issue 997](https://github.com/actions/dependency-review-action/issues/997)).
  The maintainers' rationale is the completeness problem: _"a license deny list
  is a bad idea… it's easy to miss commercial licenses like Elastic."_ A
  blocklist gives false security — you are always one new copyleft/commercial
  variant behind.
- **An allow-list fails CLOSED on unexpected _detected_ licenses.** Anything
  detected and not on the list fails the PR, so copyleft/commercial
  introductions are blocked by omission — no enumerate-every-bad-id treadmill.
  This is the right posture for the repo's FOSS-only governance line (the same
  one that rejected k6/AGPL in #73 and removed Renovate/AGPL).

The allow-list is the **exhaustive set of permissive licenses actually present
in the tree** (verified with `license-checker`), so it does not false-positive
on the current dependencies. Refresh it when a new permissive dependency is
introduced — the PR adding that dependency will flag it here, which is the
intended review point.

### License-family taxonomy (the rationale, by family)

| Family                      | Examples                                        | Verdict                   |
| --------------------------- | ----------------------------------------------- | ------------------------- |
| Permissive                  | MIT, Apache-2.0, BSD-2/3, ISC, 0BSD, BlueOak    | ✅ allow-listed           |
| Weak / file-level copyleft  | LGPL-\*, MPL-2.0, EPL-1.0/2.0                   | ❌ not allowed            |
| Strong copyleft             | GPL-2.0, GPL-3.0                                | ❌ not allowed            |
| Network copyleft            | AGPL-3.0                                        | ❌ not allowed (#73 line) |
| Source-available / non-FOSS | SSPL-1.0, BUSL-1.1, Elastic-2.0, Commons-Clause | ❌ not allowed            |

Everything below "permissive" is blocked simply by **not being on the
allow-list** — there is no list of bad ids to maintain.

### Enforced `allow-licenses`

See `security.yml` → `dependency-review` job:
`MIT, Apache-2.0, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD, BlueOak-1.0.0,
Python-2.0, CC0-1.0, CC-BY-4.0, Unlicense`.

### Known limitations (documented, not hidden)

- **Undetected/unlicensed dependencies pass `dependency-review` silently** —
  per the action's docs, _"if we can't detect the license… the action won't
  fail."_ This is true in both allow- and deny-list modes. **Trivy's license
  scan is the intended full-tree backstop** for the `UNKNOWN` case (separate
  follow-up, tracked under #77).
  - **"Could not detect a license" on a _brand-new_ release is usually harvest
    lag, not a license problem.** GitHub sources PyPI license data from
    [ClearlyDefined](https://clearlydefined.io), whose scan of a
    days-old release often hasn't run yet (observed with `aiohttp` 3.14.1: PyPI
    wheel `METADATA` says `Apache-2.0 AND MIT`, ClearlyDefined `declared: null`,
    score 0, no harvest tools run). The procedure when a PR shows UNKNOWN:
    1. **Verify against the primary source** — read the wheel/sdist `METADATA`
       `License:` / `License-Expression:` field on PyPI (stronger evidence than
       any aggregator).
    2. **Queue an upstream harvest** to shorten the lag —
       `curl -X POST https://api.clearlydefined.io/harvest -H 'Content-Type: application/json' -d '{"tool":"package","coordinates":"pypi/pypi/-/<name>/<version>"}'`
       (no auth required; returns `201 Created`; no evidence payload — their
       own tooling re-scans the artifact).
    3. **File (or update) a `license-review`-labeled issue** for the purl,
       recording the METADATA verdict from step 1 and the ClearlyDefined
       definition link
       (`https://clearlydefined.io/definitions/pypi/pypi/-/<name>/<version>`).
       **Steps 2–3 are automated (#127 Leg B):** a triage step in the
       `dependency-review` job queues the harvest and files the issue at PR
       time for each `unlicensed` pypi purl, and the weekly
       `license-review-poller.yml` workflow then auto-closes the issue when
       ClearlyDefined's declared license is satisfiable from `security.yml`'s
       `allow-licenses` (the single source, extracted at runtime; SPDX
       satisfiability in `.github/scripts/license-verdict.mjs` —
       conservative: unparseable/`NOASSERTION` never passes), escalates
       (`priority:high` + `area:security`) after 30 days unresolved, and on
       an _unacceptable_ declared license escalates AND fails its run red —
       the enforcement point for packages that merged while UNKNOWN, which
       the PR-diff-scoped gate can never re-check. The warning itself is
       self-expiring (dependency-review is PR-diff-scoped, so it only
       reappears on a PR touching that package) and never fails the gate, so
       no suppression is needed meanwhile.

    As a **last resort only** — e.g. a future config where unlicensed deps
    _do_ fail the gate and a release must ship before the harvest lands — the
    action supports `allow-dependencies-licenses` exemptions. **Caution: it
    matches exemption purls by package name only (the `@version` is
    ignored)**, so an entry silences license checking for _every_ future
    version of that package. The steady state is an empty/absent list (#127);
    any entry added under duress must carry the verified license, evidence,
    and drop condition in a comment and be removed the moment ClearlyDefined
    catches up.

- **Dual licenses such as `(MIT OR GPL-3.0-or-later)`, `(MIT OR CC0-1.0)`,
  `(BSD-2-Clause OR MIT OR Apache-2.0)` stay GREEN** — the SPDX `OR` expression
  is satisfied by an allowed member. `case@1.6.3` (`MIT OR GPL-3.0-or-later`)
  in the current tree is exactly this case; its GPL side is moot and it is not
  a violation.
- **Riders such as `Commons-Clause`** (e.g. `MIT AND Commons-Clause`) are not
  valid standalone SPDX ids; an `AND`-rider expression is allowed only if every
  member is allow-listed, so a Commons-Clause rider would fail (Commons-Clause
  is not on the list). Trivy's license scan remains the authoritative catch for
  riders the SPDX expression doesn't surface.

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

## Accepted risks (documented, not suppressed)

A finding stays open in a scanner or Dependabot only when a real, proven fix is
preferred — see "Remediating a scanner finding" above. The exceptions below are
**accepted risks**: no fix exists to apply _and_ the vulnerable path is not
reachable in this repo's usage. Each is documented here and dismissed at source
with a matching rationale, and re-opens the moment an upstream fix ships.

- **`ecdsa` (pip) — GHSA-wj6h-64fc-37mp / CVE-2024-23342 ("Minerva" timing
  side-channel), high.** A transitive dependency of checkov, pinned in
  `.github/scanner-requirements/iac.txt` (`ecdsa==0.19.2`). **No fix to pin
  to:** upstream `python-ecdsa` treats side-channel resistance as out of scope,
  so the advisory's `first_patched_version` is **null** — there is no fixed
  release. **Not reachable here:** Minerva is only exploitable when the library
  performs ECDSA **signing** (`sign_digest`, private-key operations) with
  attacker-observable timing; this repo only runs checkov to scan local
  synthesized CloudFormation templates **offline** — no signing, no private
  keys, no attacker timing channel. Tracked as Dependabot alert #13, dismissed
  `tolerable_risk`. **If a fix ever ships**, it flows through the same
  coupled-closure mechanism as the `aiohttp==3.14.1` override (§ Dependency
  notes / `overrides.txt`, AGENTS.md): add the floor to
  `.github/scanner-requirements/overrides.txt`, recompile `iac.txt` with
  `--require-hashes`, and install `--no-deps`.

## Pinning

All scanner tools are pinned (action SHA / binary checksum / pinned version) per
[PINNING.md](PINNING.md). The two actions added for the supply-chain work
(`dependency-review-action` v5.0.0, `sbom-action` v0.24.0) are SHA-pinned like
every other `uses:` and are registered as future targets of the #78 pin-sync
updater.
