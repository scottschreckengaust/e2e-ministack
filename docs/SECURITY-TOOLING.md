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

| Gate                  | Workflow     | Scope                                       | Failure policy        |
| --------------------- | ------------ | ------------------------------------------- | --------------------- |
| CodeQL (JS/TS)        | security.yml | SAST over source                            | hard-fail             |
| Semgrep               | security.yml | SAST over source                            | hard-fail             |
| npm audit             | security.yml | npm advisories (`--audit-level=high`)       | hard-fail             |
| OSV-Scanner           | security.yml | lockfile advisories                         | hard-fail             |
| Grype (FS)            | security.yml | filesystem vuln scan                        | hard-fail             |
| Grype (MiniStack img) | security.yml | third-party emulator image by digest        | hard-fail (VEX-gated) |
| Trivy (FS)            | security.yml | filesystem vuln scan (2nd DB vs Grype)      | report-only           |
| Trivy (MiniStack img) | security.yml | third-party emulator image by digest        | hard-fail (VEX-gated) |
| **dependency-review** | security.yml | PR dep-diff: vulns + **license policy**     | hard-fail (PR)        |
| **SBOM (Syft)**       | security.yml | CycloneDX SBOM of the tree                  | informational         |
| ClamAV                | security.yml | working-tree virus/malware signature scan   | hard-fail             |
| SonarQube             | security.yml | code quality + security (Community edition) | report-only           |
| Gitleaks              | security.yml | secrets (full history)                      | hard-fail             |
| checkov + cfn-lint    | security.yml | synthesized CloudFormation                  | hard-fail             |
| Threat model          | security.yml | `threat-model.tc.json` parses/sections      | hard-fail             |
| actionlint + zizmor   | security.yml | workflow correctness + security             | hard-fail             |

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
  scan is the intended full-tree backstop** for the `UNKNOWN` case. Trivy is
  wired (#133) as a **vuln** scanner (see "Trivy" above — `trivy-fs` report-only,
  `trivy-image` hard-fail + VEX per #84); enabling its **license** scan as the
  enforced UNKNOWN backstop is still future work (#77 scope), not covered here.
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

## Trivy (second vuln scanner) — #133

Trivy ([Aqua Security](https://github.com/aquasecurity/trivy)) runs as a second
vulnerability scanner alongside Grype, wired in #133. Two jobs in `security.yml`,
mirroring the Grype pair, with a **split failure policy** (set by #84):

- **`trivy-fs`** — `trivy fs .` filesystem scan (Trivy analog of the Grype FS
  job). **Report-only** (mirrors the filesystem posture; no VEX).
- **`trivy-image`** — vuln scan of the **pinned MiniStack emulator image by
  digest** (Trivy analog of the `ministack-image` Grype job); the digest is kept
  in sync across `ci.yml` + both Grype/Trivy jobs. **Hard-fail, VEX-gated** — see
  "MiniStack image scan" below.

Both follow the repo's **produce → always-upload → enforce** shape. `trivy-fs`'s
enforce step is report-only (logs the outcome, never fails); `trivy-image`'s
enforces (`test "$outcome" = "success"`). Each emits SARIF to the **Security
tab** (categories `trivy-fs` / `trivy-image`) plus a table artifact.

**Why a second scanner (deliberate overlap with Grype).** Grype and Trivy use
**different vulnerability databases**, so they surface **different CVEs** on the
same target — running both widens coverage rather than duplicating it. On the
pinned MiniStack image the high+ sets genuinely diverge: **47 (Grype) ∪ 27
(Trivy) = 50 union** CVEs (24 in both, 23 Grype-only, 3 Trivy-only) — including
severity disagreements (Grype rates the glibc CVEs Critical/High that Trivy rates
Medium/Low). Trivy is also the **intended full-tree backstop** for the
license-UNKNOWN / rider gap that `dependency-review`'s list mode can't fail
closed on (see "Known limitations" above; #77 scope).

**Governance verdict (tool-adoption).** Trivy (Aqua Security) and its
`trivy-action` are both **Apache-2.0** — permissive, no copyleft, no
single-vendor lock-in — so Trivy satisfies the repo's FOSS-only tool-adoption
line (the same line that rejected k6/AGPL in #73 and Renovate/AGPL in #80). #84
adds **no new tool**: the OpenVEX records are **hand-authored JSON** consumed by
the already-adopted Grype/Trivy `--vex` inputs (no `vexctl` binary), so it clears
the tool-adoption gate without a new dependency.

## ClamAV virus scan (#149)

The `clamav` job runs [ClamAV](https://www.clamav.net/) (Cisco Talos, GPLv2) as
a signature-based malware scan of the working tree. ClamAV is invoked as an
**external scanner** — a `clamav/clamav` Docker service container plus the apt
`clamdscan` client over loopback TCP — never linked or redistributed into repo
output, the identical carve-out that clears **shellcheck (GPLv3)**. So it adds
no copyleft dependency and needs no tool-adoption exception.

- **Signatures float by design.** The pinned `clamav/clamav` image runs
  `freshclam` at container start, pulling the current virus CVDs before clamd
  reports healthy — so every run scans with up-to-date signatures. This mirrors
  the Trivy/Grype floating-vuln-DB rationale: the image is pinned by **digest**
  (reproducible engine), the signature **data** floats (fresh coverage). No
  signature DB is committed.
- **SARIF.** clamdscan has no machine-readable output, so
  `.github/scripts/clamav-to-sarif.mjs` parses its text log (`PATH: SIG FOUND`
  lines) into SARIF 2.1.0 (category `clamav`). A virus-signature match is
  unambiguously critical, so every finding maps to `level: error` /
  `security-severity: 10.0`. A clean tree yields a valid empty-results SARIF.
- **Hard-fail** via produce → always-upload → enforce: `clamdscan` exits
  non-zero on any detection; the SARIF + text log always upload first, then the
  enforce step fails the job.
- **Verifying detection (EICAR).** A green run only proves no false-positive. To
  prove the gate FIRES, use the
  [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) — a
  harmless 68-byte string every AV flags as `Win.Test.EICAR_HDB-1`. Write it to
  a **throwaway/ignored** path and confirm clamdscan exits non-zero and the
  converter emits one `error` result. **Never commit EICAR** to a tracked path —
  the job scans `.`, so a committed sample makes CI permanently red. The
  converter's parser is unit-tested against captured log text instead
  (`clamav-to-sarif.test.mjs`, run with `node --test`).

## SonarQube analysis (#150) — governance exception

The `sonarqube` job runs **SonarQube Community** fully credential-free against a
service container (self-generates a scanner token via the first-boot admin API —
`admin/admin`, SonarQube's documented default for a fresh instance, passed via
env so it is not a literal `-u user:pass` the gitleaks `curl-auth-user` rule
flags), then derives SARIF from the analysis results.

**Governance — a maintainer-approved exception.** The two SonarSource actions
(`sonarqube-scan-action`, `sonarqube-quality-gate-action`) are **LGPL-3.0**, and
SonarQube is a **single-vendor** SonarSource product. Two separable concerns:

1. **Copyleft.** Mitigated by the same **CI-only external-invocation carve-out**
   as ClamAV/shellcheck: these are `uses:` actions invoked in the pipeline, never
   linked or redistributed into repo output, so their copyleft terms don't reach
   it. The `dependency-review` gate (which sees the action as a dependency)
   exempts it via `allow-dependencies-licenses` with a purl (#161).
2. **Single-vendor.** SonarQube is a SonarSource product — the genuine deviation
   from the single-vendor line that rejected k6 (#73) and Renovate (#80),
   accepted here as a **deliberate, documented exception** by the maintainer,
   recorded on the PR. Not a silent override.

- **SARIF is derived by an in-repo converter, NOT `okorach/sonar-tools`.** The
  obvious native exporter (`sonar-tools --format sarif`) was **rejected on
  governance grounds**: `sonar-tools==3.21` hard-requires `levenshtein`
  (**GPL-2.0-or-later**, strong copyleft) in its `requires_dist` — beyond the
  LGPL exception above and a _new_ copyleft piece the maintainer did not approve.
  Instead `.github/scripts/sonar-to-sarif.mjs` re-shapes the `api/issues/search`
  JSON the job already fetches into SARIF (category `sonarqube`): **zero new
  dependencies, zero copyleft, no Python step.** It maps Sonar severity (legacy
  `BLOCKER…INFO` and the newer `impacts[]` HIGH/MEDIUM/LOW) to SARIF
  `error/warning/note`, resolves file paths via the response `components[]`, and
  converts 0-based `textRange` offsets to 1-based SARIF columns. Unit-tested with
  `node --test` (`sonar-to-sarif.test.mjs`).
- **Failure policy: report-only.** The default "Sonar way" quality gate is tuned
  for application repos and would be noisy on first run, so the enforce step
  **logs** the gate status and never fails the job — exactly mirroring the
  `trivy-fs` report-only posture. **Ratchet:** a follow-up flips it to
  `test "$QG_STATUS" = "PASSED"` once the baseline is triaged / the quality
  profile is tuned.
- **Semgrep false-positive (maintainer-approved, TEMPORARY rule exclude).** The
  generic secrets rule `generic.secrets.security.detected-sonarqube-docs-api-key`
  matches `sonar…<40-hex>`, which the pinned image **digest** and the two
  commit-**SHA** action pins unavoidably are (SHA-pinning SonarSource's own
  actions is required by the repo's pinning rules). These are public, required
  pins — not API keys. Cleared with a single **`--exclude-rule`** on the semgrep
  invocation, **not** inline `# nosemgrep`. Why `--exclude-rule` and not
  `nosemgrep`: `# nosemgrep` marks the finding `suppressions:[{inSource}]` but
  **leaves the result in the SARIF**, and GitHub Code Scanning still ingests and
  surfaces it — reddening the `Semgrep OSS` check that consumes our uploaded
  SARIF. `--exclude-rule` drops the rule entirely (0 results), clearing both the
  gate and the Code Scanning alert. Scoped to this ONE rule, so every other
  secret/SAST rule still runs on the whole tree (including `docs/`). This is a
  genuinely-unfixable true-false-positive with the maintainer sign-off the
  "Remediating a scanner finding" section requires, and it is **temporary**:
  **remove the `--exclude-rule` once the upstream fix
  ([semgrep/semgrep-rules#3994](https://github.com/semgrep/semgrep-rules/pull/3994))
  lands in `r/all`** — tracked by #163, and folded into the vendored ruleset
  under #79. Until a Semgrep pre-commit hook exists (#79), the exclude lives only
  in CI; when that hook is added it must carry the same `--exclude-rule`.

### dependency-review `allow-dependencies-licenses` (#161)

`#161` evaluated whether the awslabs `config-file` / `allow-dependencies-licenses`
pattern could replace the bespoke license machinery. **Finding:** `config-file`
is a PR-time policy-location change and is **orthogonal** to
`license-review-poller.yml`, which is the _post-merge_ enforcement for the
ClearlyDefined harvest-lag hole (#127 Leg B) — so adopting awslabs wholesale
would DELETE that enforcement, not simplify it. **Decision: Option A** — keep the
inline `allow-licenses` allow-list and the poller unchanged, and adopt ONLY the
per-dependency `allow-dependencies-licenses` exemption for the LGPL SonarQube
action. **#161 Q1 (match semantics) — RESOLVED:** verified against the pinned
action's `src/purl.ts` that `purlsMatch` compares `type` + `namespace/name` and
**ignores the version** — so `allow-dependencies-licenses` matches **by name
only**. The `@<sha>` in the exemption purl is cosmetic; a future SHA/version bump
does **not** re-trigger the license review (contradicting the awslabs example's
comment). That is acceptable here — the action is LGPL at every version, so it is
intentionally permanently exempt while in use.

## MiniStack image scan — hard-fail, VEX-gated (#84)

The `ministack-image` (Grype) and `trivy-image` (Trivy) jobs are **hard-fail**:
they fail CI on any high+ CVE in the pinned emulator image that is **not** covered
by an OpenVEX record under `.vex/`. The ~50 unfixable base-image CVEs (the Grype
∪ Trivy union above) are each accepted via an individual
`.vex/CVE-XXXX.openvex.json` file, so the gate is green today and fails only on a
**new** CVE — the actionable signal (VEX-accept it, or bump the digest once
MiniStack ships a fix).

**Why `not_affected`, not `affected`.** The intuitive record for "we accept this
risk" is `status: affected` + `action_statement`. **Neither Grype nor Trivy will
suppress an `affected` finding** — proven empirically at the pinned versions in
**PR #160**:

- Grype v0.110.0 (`anchore/scan-action` v7.4.0): `grype/vex/openvex/`
  `implementation.go` `FilterMatches` moves only `not_affected`/`fixed` to the
  ignored set; `AugmentMatches` _re-surfaces_ `affected` matches (the `vex-add`
  path is "show these", not "hide these"). An `affected` + `vex-add`/`ignore`
  config left the findings present (`--fail-on high` still exited non-zero).
- Trivy v0.70.0 (`aquasecurity/trivy-action` v0.36.0): `pkg/vex/openvex.go`
  `Filter` suppresses only `not_affected`/`fixed`.

So the honest, **working** path is **`status: not_affected`** with a truthful
justification enum. We use **`vulnerable_code_cannot_be_controlled_by_adversary`**
— a genuine adversary-reachability claim, not a false "code not present": MiniStack
is a local-only CI emulator (binds port 4566 on loopback, ephemeral per-run
container, never network-exposed, exercised only by this repo's own CDK/SDK test
traffic, not a deployed/production artifact), so no adversary can supply the
crafted input that would reach the vulnerable code. The full accepted-risk prose
and fix state live in each record's `impact_statement`. This is an **honest,
machine-readable, per-CVE risk acceptance** — the sanctioned form, distinct from a
blanket `nosemgrep`/ignore that asserts false safety (see "Remediating a scanner
finding" above). The 7 fixed-upstream python CVEs carry a distinct "awaiting a
MiniStack image rebuild" note plus an upstream advisory link and are dropped the
moment a rebuilt digest ships patched python.

**How the records are fed (the channels differ per scanner — this is a real
gotcha).** Both scanners' `--vex` takes explicit **file paths** (neither accepts a
bare directory or globs), but the two CI actions surface it differently:

- **Grype** — the `ministack-image` job gathers `.vex/CVE-*.openvex.json` into a
  comma-separated list at runtime and passes it via the **`GRYPE_VEX_DOCUMENTS`
  env**, which the `anchore/scan-action` forwards to grype natively (grype reads
  its whole config from env). Verified working in CI.
- **Trivy** — the `aquasecurity/trivy-action` v0.36.0 has **no `vex` input and
  does NOT forward a `TRIVY_VEX` env** to trivy's `--vex` flag (its entrypoint
  runs `trivy <type> <ref>` with no extra flags), so the env route silently loads
  **zero** VEX docs and the gate wrongly fires. The working channel is the
  committed **`trivy.yaml`'s `vulnerability.vex` list** (the 50 image CVE file
  paths), which trivy **auto-discovers from the CWD** regardless of the action.
  Because `trivy.yaml` is shared with the report-only `trivy-fs` job, the records
  are image-package purls that don't match any source-tree component, so they're
  inert there. (Also: the action UNSETS `TRIVY_SEVERITY` for SARIF output, so the
  `trivy-image` job sets the floor + `exit-code` via the action's
  `severity`/`exit-code`/`limit-severities-for-sarif` **inputs**, not env.)

Either way the `.vex/CVE-*` set is the single source of truth; a new/removed CVE
record means one line added/removed in `trivy.yaml` (the grype side is glob-driven
and needs no edit). See `.vex/README.md`.

**Product PURL structure — qualifier-less, and why (a real cross-scanner gotcha).**
OpenVEX matching is per-PRODUCT, and [go-vex](https://github.com/openvex/go-vex)
(used by both scanners) only matches when the statement's product purl equals the
scanned component's purl, **including qualifiers**. Grype and trivy emit
**different** purls for the same image package: grype `?arch=amd64&distro=debian-13`,
trivy `?arch=all&distro=debian-13.5` (trivy also tracks the distro _minor_). So a
record carrying one scanner's full purl silently fails to match the other — this
is exactly why the first hard-fail attempt passed grype but the image CVEs came
through unfiltered in trivy. The fix: each `products[].@id` is a **qualifier-less
base purl** (`pkg:deb/debian/<name>@<version>`, `pkg:generic/python@<version>`),
which matches BOTH scanners regardless of arch / distro-minor. Debian **epochs** are
a second wrinkle — grype keeps the epoch in the version (`name@1:2.41-5`), trivy
strips it (`name@2.41-5`); those records list **both** version forms as products.
Verified against grype v0.110.0 (SBOM) and trivy v0.70.0 (`trivy image <digest>`,
the real CI path): both exit 0, all high+ suppressed. **When adding a record for a
new CVE, use the qualifier-less purl (and add the epoch-less form if the version has
an epoch)** — not the raw scanner SARIF purl.

**Severity-cutoff ratchet plan.** The image gate starts at `severity-cutoff: high`
(Grype) / trivy's `severity: HIGH,CRITICAL` action input (with
`limit-severities-for-sarif: true`, because the trivy-action otherwise unsets the
severity filter on SARIF output) — the smallest acceptable starting set. The end state is "fail on **any** new CVE at the configured floor,
with every accepted one explicitly VEX'd." The floor is a **documented, ratcheting
value**: once the high+ set is under VEX control and CI is green, progressively
lower it — **high → medium → low** — VEX-accepting the newly-surfaced
lower-severity base-image CVEs the same honest way. **Each lowering is its own
reviewable batch of VEX additions** — do not lower below `high` in the same change
that introduces the gate. The `.vex/` staleness + the cutoff value are audit
targets of **#76**.

**`.vex/` drift (#76).** Every record must still match a live finding; resolved
ones (digest bump drops a CVE, or upstream-fixed python reaches the image) are
pruned by the #76 drift audit. A new uncovered high+ CVE fails the gate until
VEX-accepted or the digest is bumped.

**`trivy-config` (cdk.out misconfig) — deferred as checkov-redundant (YAGNI).**
A Trivy config/IaC scan of the synthesized `cdk.out` templates was
**deliberately omitted**: that surface is already the REQUIRED `iac` gate
(checkov + cfn-lint), so a Trivy config job would duplicate IaC coverage for no
new signal here. #133 scope was vuln scanning (FS + image); add `trivy-config`
later only if a concrete gap in checkov's CloudFormation coverage is identified.

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
updater. `trivy-action` (v0.36.0, added in #133) is likewise SHA-pinned and is
also a #78 pin-sync target; its vuln **database floats** by design (like
Grype's), so newly disclosed CVEs are caught without a repo change — the DB is
cached across runs via `actions/cache` (see PINNING.md).
