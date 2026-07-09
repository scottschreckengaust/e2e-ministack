# Design: ClamAV (#149) + SonarQube (#150) security jobs

**Date:** 2026-07-09
**Branch:** `feat/security-scanners-clamav-sonarqube`
**Issues:** #149 (virus scanning / ClamAV), #150 (more security / SonarQube)
**Related:** #161 (dependency-review config-file vs. poller — filed during brainstorming, not implemented here)

## Goal

Add two new scanner jobs to `.github/workflows/security.yml`, modeled on
[`awslabs/agent-plugins` `security-scanners.yml`](https://github.com/awslabs/agent-plugins/blob/main/.github/workflows/security-scanners.yml)
(the `sonarqube` and `clamav` jobs), adapted to this repo's conventions:

- **ClamAV (#149)** — signature-based malware/virus scan of the working tree.
- **SonarQube (#150)** — SonarQube Community code analysis + quality gate, run
  fully credential-free against a service-container instance.

Both derive **SARIF** and upload it to the GitHub Security tab (the awslabs
reference is artifact-only; SARIF is net-new here to match this repo's
"SARIF-capable scanners also `upload-sarif`" convention).

All image digests + action SHAs are updated to current latest and pinned.

## Governance decisions (recorded — these gate the work)

This repo treats every new tool/action as a **license + single-vendor** decision
(AGENTS.md tool-adoption line; the line that rejected k6/AGPL #73 and Renovate #80).
Both decisions below were **escalated to and approved by the maintainer** during
brainstorming (2026-07-09).

### ClamAV — governance-clean

ClamAV is GPLv2, but invoked as an **external scanner** (Docker service +
apt `clamdscan` over loopback TCP), never linked or redistributed into any
artifact. This is the identical carve-out the repo already documents for
**shellcheck (GPLv3)** — "invoked as an external linter … adds no copyleft
dependency." The job only `uses:` already-pinned `checkout` + `upload-artifact`
(+ `upload-sarif`). No new governance surface.

### SonarQube — accepted exception (maintainer-approved)

Two separable concerns, recorded honestly:

1. **Copyleft.** `SonarSource/sonarqube-scan-action`,
   `SonarSource/sonarqube-quality-gate-action`, and `okorach/sonar-tools`
   (the SARIF exporter — see below) are all **LGPL-3.0**. Mitigated by the same
   external-invocation carve-out as ClamAV/shellcheck: they are CI-only
   (`uses:` actions / a pip-installed CLI), never linked or redistributed into
   repo output, so their copyleft terms don't reach it. This matches the
   awslabs precedent, which exempts the same `sonarqube-scan-action` as
   "a CI-only action we invoke … not code we distribute or link."
2. **Single-vendor.** SonarQube is a SonarSource product. This is the genuine
   deviation from the k6/Renovate single-vendor line, accepted as a **deliberate,
   documented exception** by the maintainer. Recorded in
   `docs/SECURITY-TOOLING.md` and the PR body — not a silent override.

## Architecture

Two jobs appended to `security.yml`, each following the repo's canonical
**produce → always-upload → enforce** shape (run tool with `set +e` /
`continue-on-error`, persist exit to a `*.outcome` file, `if: always()` upload
the report(s) + SARIF, final `if: always()` step enforces the saved outcome).
This guarantees the diagnostic artifact exists precisely when the job fails —
the invariant every other gate in this workflow honors.

Both use **plain GitHub Actions service containers** (self-contained, one TCP
port each). This is NOT the MiniStack sibling-container model, so the AGENTS.md
"no `services:`" constraint (which is specific to MiniStack needing host
networking + the Docker socket) does not apply.

Every checkout adds `persist-credentials: false` (repo/zizmor requirement; the
awslabs reference omits it).

### Job: `clamav`

- **Service container:** `clamav/clamav` pinned by digest
  `sha256:6f4a9e7d616ffc8d1070200fe35ac860735fdd522161a1043f94856e6ee13c28`
  (current `stable`; reference had older `a56287b…`). Port bound
  `127.0.0.1:3310:3310` (loopback-only). Health via the image's own
  `clamdcheck.sh` (do NOT override — the image ships its own healthcheck;
  same lesson as MiniStack's healthcheck note).
- **Steps:**
  1. checkout (`persist-credentials: false`)
  2. wait for clamd on `127.0.0.1:3310`
  3. `apt-get install -y --no-install-recommends clamdscan`; write
     `/etc/clamav/clamd.conf` (`TCPSocket 3310` / `TCPAddr 127.0.0.1`)
  4. `set +e; clamdscan --verbose --log=clamdscan.txt --stream --fdpass --multiscan .;`
     `echo "exit=$?" > clamav.outcome`
  5. **Derive SARIF** (bespoke — clamdscan has no machine-readable output):
     `node .github/scripts/clamav-to-sarif.mjs clamdscan.txt clamav.sarif`.
     Parses `FILE: SIGNATURE FOUND` lines → one SARIF result each,
     `level: "error"`, `security-severity: "10.0"` (a virus-signature match is
     unambiguously critical), `physicalLocation.artifactLocation.uri` = the file.
     A clean scan → valid **empty-results** SARIF (uploads fine, shows "no
     findings").
  6. `upload-sarif` (category `clamav`) — `if: always()`
  7. `upload-artifact` `clamdscan.txt` (+ `clamav.sarif`) — `if: always()`,
     `if-no-files-found: warn` (reference used `error`; `warn` matches this repo)
  8. **Enforce:** `source clamav.outcome; test "$exit" = "0"` — `if: always()`.
- **Permissions:** `contents: read` + `security-events: write` (for SARIF upload).
- **Failure policy:** **hard-fail.** `clamdscan` exits non-zero on any detection.
  The repo tree (incl. `fuzz/corpus/` seed bytes) won't trip signature detection,
  so a clean repo passes immediately.
- **"Latest database pulls" (#149):** satisfied by construction. The
  `clamav/clamav` image runs `freshclam` at container start, pulling current
  virus CVDs from the ClamAV mirror before clamd reports healthy — so the scan
  always uses fresh signatures. No signature DB is committed. Pinning to the
  current `stable` digest keeps the baked-in snapshot recent too. Documented in
  PINNING.md as a **floating signature DB**, analogous to Trivy's/Grype's
  floating vuln DB (binary/image pinned, data floats by design).

### Job: `sonarqube`

- **Service container:** `sonarqube:community` pinned by digest
  `sha256:160bd2f6a3485bd09b655ef22dd63c02bd1fa7ba82aa5d9973fd010b8bcca0b3`
  (current; reference had older `48dd0e9…`). `env: SONAR_ES_BOOTSTRAP_CHECKS_DISABLE: true`,
  `SONAR_WEB_SYSTEMPASSCODE: passcode`. Port `127.0.0.1:9000:9000`. Health via
  the reference's `wget`-based `--health-cmd` polling `api/system/status = UP`.
- **Steps (credential-free, all local):**
  1. checkout with `fetch-depth: 0` (Sonar wants full history for blame/new-code),
     `persist-credentials: false`
  2. pinned Python 3.12 (`actions/setup-python`, same pin as `iac`/`semgrep`)
  3. wait for `api/system/status == UP`
  4. generate a token via first-boot `admin:admin` → `api/user_tokens/generate`;
     export to `$GITHUB_ENV` as `SONAR_TOKEN`
  5. create project `my-project`
  6. `SonarSource/sonarqube-scan-action@713881670b6b3676cda39549040e2d88c70d582e`
     (v8.2.0) with `SONAR_HOST_URL=http://localhost:9000`, `SONAR_TOKEN` from env
  7. `SonarSource/sonarqube-quality-gate-action@cf038b0e0cdecfa9e56c198bbb7d21d751d62c3b`
     (v1.2.0), `continue-on-error: true`, capture the gate status
  8. **Derive SARIF** via **`okorach/sonar-tools`** native exporter (maintainer's
     chosen path over bespoke/community — battle-tested native `--format sarif`):
     install pinned via a new `.github/scanner-requirements/sonar-tools.txt`
     (`pip install --require-hashes`), then
     `sonar-findings-export -u http://localhost:9000 -t "$SONAR_TOKEN" -k my-project --format sarif -f sonar.sarif`.
     Also keep the raw `sonar-issues.json` (`api/issues/search`) artifact for
     parity with the reference.
  9. `upload-sarif` (category `sonarqube`) — `if: always()`
  10. `upload-artifact` (`sonar.sarif` + `sonar-issues.json`) — `if: always()`
  11. **Enforce** per failure policy (below) — `if: always()`.
- **Permissions:** `contents: read` + `security-events: write`.
- **zizmor hardening (the reference is NOT zizmor-clean — must fix):** the
  reference inlines `${{ env.SONAR_TOKEN }}` and `${{ steps.*.outputs.* }}`
  directly into `run:` blocks (template-injection findings). Rewrite EVERY
  `run:` to read `$SONAR_TOKEN` / gate-status from the shell `env:` block —
  never inline `${{ }}` into `run:`. This is the repo's no-template-injection
  rule (enforced by the zizmor job in this same workflow).
- **SARIF exporter governance:** `okorach/sonar-tools` is **LGPL-3.0** and on
  PyPI (`sonar-tools==3.21`). Same CI-only external-invocation carve-out;
  pip-pinned with `--require-hashes` exactly like checkov/semgrep. It is the
  **third** LGPL piece in this feature — all covered by the single documented
  SonarQube exception. Registered as a #78 pin-sync target.
- **Failure policy — REPORT-ONLY → ratchet (maintainer-confirmed 2026-07-09).**
  The default "Sonar way" quality gate flags maintainability smells tuned for
  app repos and would be noisy on first run; hard-failing on day one would
  redden `main` for non-security signal. So the enforce step **LOGS** the
  quality-gate status (from the `quality-gate-action` output, passed via `env:`)
  and **never fails the job**, exactly mirroring how `trivy-fs` landed
  report-only. The SARIF still lands in the Security tab regardless. This is a
  documented **ratchet**: a follow-up flips the enforce step to
  `test "$gate" = "PASSED"` once the baseline is triaged / the quality profile
  is tuned. Recorded alongside the trivy-fs report-only precedent in
  `docs/SECURITY-TOOLING.md`.

## Pins (all current latest, SHA/digest-pinned)

| Item                            | Pin                                                                       |
| ------------------------------- | ------------------------------------------------------------------------- |
| `sonarqube-scan-action`         | `v8.2.0` → `713881670b6b3676cda39549040e2d88c70d582e`                     |
| `sonarqube-quality-gate-action` | `v1.2.0` → `cf038b0e0cdecfa9e56c198bbb7d21d751d62c3b`                     |
| `okorach/sonar-tools`           | `3.21` (PyPI, `--require-hashes` in `sonar-tools.txt`)                    |
| `clamav/clamav` image           | `sha256:6f4a9e7d616ffc8d1070200fe35ac860735fdd522161a1043f94856e6ee13c28` |
| `sonarqube:community` image     | `sha256:160bd2f6a3485bd09b655ef22dd63c02bd1fa7ba82aa5d9973fd010b8bcca0b3` |

Reused (already pinned in-repo): `actions/checkout@9c091bb`, `actions/setup-python@ece7cb0`,
`actions/upload-artifact@043fb46`, `github/codeql-action/upload-sarif@99df26d`.

## Docs to update

- **`docs/SECURITY-TOOLING.md`** — two new gate-inventory rows (ClamAV
  **hard-fail**; SonarQube **report-only** — mirroring `trivy-fs`); a ClamAV
  subsection (external-invocation carve-out; floating signature DB); a SonarQube
  subsection (the accepted single-vendor exception + the three LGPL pieces +
  report-only→enforce ratchet plan + the sonar-tools SARIF path).
- **`docs/PINNING.md`** — register both images + both actions + `sonar-tools`;
  note ClamAV's floating signature DB (Trivy-analogous) in the "Intentionally NOT
  pinned" section; flag all as #78 pin-sync targets.
- **`AGENTS.md`** — concise bullets under "Security checks".

## Out of scope (YAGNI — with rationale)

- **ClamAV in pre-commit** (#149's "optionally … prevent commit"): declined —
  needs a running clamd + ~200 MB signature DB, violating the "fast convenience
  tier" line. Stays CI-only alongside CodeQL/Grype per the documented intentional
  pre-commit↔CI gap. Rationale to be noted on #149.
- **`config-file` / `allow-dependencies-licenses` dependency-review refactor:**
  split into its own issue **#161** during brainstorming (it's orthogonal to the
  post-merge license-review poller — see that issue). Not touched here.
- **SonarQube SCA / secrets analyzers:** Community edition scope only; not
  enabling paid analyzers.

## Testing / verification

- `actionlint` + `zizmor` must pass on the edited workflow (run locally via the
  pinned versions before pushing; both are gates in this same workflow).
- Push the branch and confirm both new jobs go green in CI (SonarQube
  report-only), SARIF appears in the Security tab under categories `clamav` /
  `sonarqube`, and artifacts upload.
- Confirm a clean tree yields an empty-results ClamAV SARIF (no false hard-fail).
- **Positive-detection check with EICAR (both directions).** A green run only
  proves the gate does not false-positive; it does NOT prove the gate actually
  _fires_ on a real detection. Verify the detection path with the
  [EICAR anti-malware test file](https://www.eicar.org/download-anti-malware-testfile/)
  — a harmless, industry-standard 68-byte string every AV engine (ClamAV
  included) is defined to flag as `Eicar-Test-Signature` (`Win.Test.EICAR_HDB-1`).
  - **Local (do not commit):** write the EICAR string to a **throwaway** file
    _outside the git tree_ (e.g. `$HOME/scratch/eicar.com`) or a path that is
    `.gitignore`d, point a local `clamdscan` at it, and confirm (a) `clamdscan`
    exits non-zero, (b) the enforce step fails, and (c)
    `clamav-to-sarif.mjs` emits **one** result with `level: "error"` /
    `security-severity: "10.0"` and the correct `physicalLocation` URI. Delete
    it immediately — gitleaks / the hygiene hooks would otherwise complain, and
    a committed EICAR file would make the `clamav` gate permanently red.
  - **Converter unit-proof (committed, safe):** rather than commit EICAR bytes,
    add a fixture of **captured `clamdscan` log text** containing a synthetic
    `FOUND` line and assert `clamav-to-sarif.mjs` maps it to the expected SARIF.
    This exercises the parser deterministically with no live virus string in the
    repo. (The generator plan — a scratch EICAR run — is recorded here so the
    verification is reproducible without hunting for the string.)
  - **Never** add EICAR to `fuzz/corpus/`, a fixture that gets scanned, or any
    tracked path — it must not reach the `clamav` job's scan target, or CI goes
    red by construction.
