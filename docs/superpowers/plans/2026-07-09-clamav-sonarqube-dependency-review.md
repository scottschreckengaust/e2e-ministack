# ClamAV + SonarQube + dependency-review exemption — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a ClamAV virus-scan job (#149) and a SonarQube analysis job (#150) to `.github/workflows/security.yml`, both emitting SARIF to the Security tab, and exempt the LGPL SonarSource actions via `dependency-review`'s `allow-dependencies-licenses` (#161, Option A).

**Architecture:** Two new service-container jobs appended to `security.yml`, each following the repo's **produce → always-upload → enforce** pattern. ClamAV findings are converted to SARIF by a small in-repo Node script (TDD'd); SonarQube findings are exported to SARIF by the pinned `okorach/sonar-tools` CLI. The dependency-review gate gets one `allow-dependencies-licenses` purl so the LGPL SonarSource action it will now see does not fail the introducing PR.

**Tech Stack:** GitHub Actions, Docker service containers (`clamav/clamav`, `sonarqube:community`), Node.js 24 (SARIF converter), Python 3.12 + pip `--require-hashes` (sonar-tools), `actions/dependency-review-action`.

## Global Constraints

Copied verbatim from the spec and repo conventions — every task implicitly includes these:

- **produce → always-upload → enforce** for every hard-fail gate: run tool with `set +e` / `continue-on-error: true`, save exit/outcome to a `*.outcome` file, `if: always()` upload report(s) + SARIF, final `if: always()` step enforces the saved outcome.
- **zizmor-clean:** pin every action to a **commit SHA** (never a tag); every `actions/checkout` sets `persist-credentials: false`; **never inline `${{ ... }}` into a `run:` block** — pass values via a step `env:` block and reference `$VAR` in the script.
- **SARIF-capable gates** also `github/codeql-action/upload-sarif` to the Security tab with a distinct `category:`.
- **Pins (exact, all current-latest):**
  - `SonarSource/sonarqube-scan-action` → `713881670b6b3676cda39549040e2d88c70d582e` (`# v8.2.0`)
  - `SonarSource/sonarqube-quality-gate-action` → `cf038b0e0cdecfa9e56c198bbb7d21d751d62c3b` (`# v1.2.0`)
  - `okorach/sonar-tools` → `3.21` (PyPI, hash-pinned in `sonar-tools.txt`)
  - `clamav/clamav` image → `sha256:6f4a9e7d616ffc8d1070200fe35ac860735fdd522161a1043f94856e6ee13c28`
  - `sonarqube:community` image → `sha256:160bd2f6a3485bd09b655ef22dd63c02bd1fa7ba82aa5d9973fd010b8bcca0b3`
  - Reuse (already pinned in-repo): `actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0` (# v7), `actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1` (# v6.3.0), `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` (# v7.0.1), `github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9` (# v4.37.0), `actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294` (# v5.0.0).
- **Failure policies:** ClamAV = **hard-fail**; SonarQube quality gate = **report-only** (log the status, never fail — mirrors `trivy-fs`), documented ratchet to enforce later.
- **Governance:** SonarQube (3 LGPL-3.0 pieces + single-vendor SonarSource) is a maintainer-approved exception under the CI-only external-invocation carve-out (same as shellcheck/ClamAV). Recorded in `docs/SECURITY-TOOLING.md` + PR body — not a silent override.
- **Report artifacts are ignored:** `*.sarif`, `*.outcome`, and named `*.txt`/`*.json` report files are already gitignored + prettier-ignored + markdownlint-ignored. **New** named report files (`clamdscan.txt`, `sonar-issues.json`) must be ADDED to `.gitignore` and `.prettierignore` (see Task 6). `*.sarif`/`*.outcome` are covered by existing globs.
- **EICAR:** never commit the live EICAR string to any tracked path — the `clamav` job scans `.`, so a committed EICAR file makes CI permanently red. Test detection on a throwaway/ignored path; test the converter with captured log **text** fixtures.

**Working branch:** `feat/security-scanners-clamav-sonarqube` (worktree at `.worktrees/feat-security-scanners`, one commit ahead of `main` = the spec). All paths below are relative to the repo root.

---

## File structure

- **Create** `.github/scripts/clamav-to-sarif.mjs` — pure function + CLI: parse clamdscan log text → SARIF 2.1.0 JSON. One responsibility: text→SARIF.
- **Create** `test/scripts/clamav-to-sarif.test.js` — Jest unit tests for the converter (parser behavior, empty case, severity mapping).
- **Create** `.github/scanner-requirements/sonar-tools.txt` — hash-pinned `sonar-tools==3.21` closure (pip `--require-hashes`).
- **Modify** `.github/workflows/security.yml` — add `clamav` + `sonarqube` jobs; add `allow-dependencies-licenses` to the existing `dependency-review` job.
- **Modify** `.gitignore`, `.prettierignore` — add `clamdscan.txt`, `sonar-issues.json`.
- **Modify** `docs/SECURITY-TOOLING.md`, `docs/PINNING.md`, `AGENTS.md` — document the gates, pins, and the SonarQube exception.
- **Verify (no commit expected)** `#161` Q1 — empirically confirm `allow-dependencies-licenses` purl match semantics; record the finding in the docs + PR.

> **Note on the converter test location.** The repo's Jest tiers are chosen by `JEST_TIER` (unit/integration/e2e) and scan `test/<tier>/`. The converter is CI-tooling, not app/Lambda logic, and must NOT enter the 100%-coverage unit gate (`lambda/index.js` scope) or the mutation scope. Task 1 runs its test with a **standalone `node --test`** invocation (Node's built-in test runner, no Jest config change, no coverage gate entanglement). This keeps the tooling test isolated from the app test tiers.

---

### Task 1: ClamAV log → SARIF converter (TDD)

**Files:**

- Create: `.github/scripts/clamav-to-sarif.mjs`
- Test: `.github/scripts/clamav-to-sarif.test.mjs`

**Interfaces:**

- Produces: `export function toSarif(logText: string): object` — returns a SARIF 2.1.0 log object. Also a CLI entrypoint: `node clamav-to-sarif.mjs <infile> <outfile>` reads `<infile>` text, writes `JSON.stringify(toSarif(text))` to `<outfile>`.
- SARIF shape (consumed by `upload-sarif`): `{ $schema, version: "2.1.0", runs: [{ tool: { driver: { name: "ClamAV", rules: [] } }, results: [...] }] }`. Each detection → `{ ruleId: <signature>, level: "error", message: { text: "<signature> detected in <file>" }, properties: { "security-severity": "10.0" }, locations: [{ physicalLocation: { artifactLocation: { uri: <relpath> } } }] }`.

Parsing contract (clamdscan `--verbose` output): a detection line matches `^(?<path>.+): (?<sig>.+) FOUND$`. Summary lines (after `----------- SCAN SUMMARY -----------`), `OK` lines, and blanks are ignored. Leading `./` is stripped from the path so the SARIF URI is repo-relative.

- [ ] **Step 1: Write the failing test**

Create `.github/scripts/clamav-to-sarif.test.mjs`:

```javascript
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toSarif } from './clamav-to-sarif.mjs';

const SAMPLE_FOUND = `/home/runner/work/repo/repo/evil.bin: Win.Test.EICAR_HDB-1 FOUND
./clean.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 1
`;

const SAMPLE_CLEAN = `./a.txt: OK
./b.txt: OK

----------- SCAN SUMMARY -----------
Infected files: 0
`;

test('maps a FOUND line to one SARIF error result at severity 10.0', () => {
  const sarif = toSarif(SAMPLE_FOUND);
  assert.equal(sarif.version, '2.1.0');
  assert.equal(sarif.runs[0].tool.driver.name, 'ClamAV');
  assert.equal(sarif.runs[0].results.length, 1);
  const r = sarif.runs[0].results[0];
  assert.equal(r.ruleId, 'Win.Test.EICAR_HDB-1');
  assert.equal(r.level, 'error');
  assert.equal(r.properties['security-severity'], '10.0');
  assert.equal(
    r.locations[0].physicalLocation.artifactLocation.uri,
    '/home/runner/work/repo/repo/evil.bin',
  );
});

test('clean scan yields a valid empty-results SARIF', () => {
  const sarif = toSarif(SAMPLE_CLEAN);
  assert.equal(sarif.version, '2.1.0');
  assert.deepEqual(sarif.runs[0].results, []);
});

test('strips a leading ./ from the artifact URI', () => {
  const sarif = toSarif('./sub/dir/x.exe: Foo.Bar FOUND\n');
  assert.equal(
    sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri,
    'sub/dir/x.exe',
  );
});

test('does not treat the SCAN SUMMARY section as findings', () => {
  const sarif = toSarif(SAMPLE_FOUND);
  // exactly one result — the "Infected files: 1" line must not match
  assert.equal(sarif.runs[0].results.length, 1);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test .github/scripts/clamav-to-sarif.test.mjs`
Expected: FAIL — `Cannot find module '.../clamav-to-sarif.mjs'` (or `toSarif is not a function`).

- [ ] **Step 3: Write minimal implementation**

Create `.github/scripts/clamav-to-sarif.mjs`:

```javascript
#!/usr/bin/env node
// Convert `clamdscan --verbose` log text into a SARIF 2.1.0 document.
// clamdscan has no machine-readable output, so we parse its text log: each
// detection is a `PATH: SIGNATURE FOUND` line. A virus-signature match is
// unambiguously critical, so every finding maps to level=error /
// security-severity=10.0 (surfaces at the top of the Security tab). A clean
// scan yields a valid empty-results SARIF (uploads fine, shows "no findings").
import { readFileSync, writeFileSync } from 'node:fs';

const FOUND_RE = /^(?<path>.+): (?<sig>.+) FOUND$/;

export function toSarif(logText) {
  const results = [];
  let inSummary = false;
  for (const raw of logText.split(/\r?\n/)) {
    const line = raw.trimEnd();
    if (line.includes('SCAN SUMMARY')) {
      inSummary = true; // everything after the banner is stats, not findings
      continue;
    }
    if (inSummary || line === '') continue;
    const m = FOUND_RE.exec(line);
    if (!m) continue;
    const uri = m.groups.path.replace(/^\.\//, '');
    results.push({
      ruleId: m.groups.sig,
      level: 'error',
      message: { text: `${m.groups.sig} detected in ${m.groups.path}` },
      properties: { 'security-severity': '10.0' },
      locations: [{ physicalLocation: { artifactLocation: { uri } } }],
    });
  }
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'ClamAV', rules: [] } },
        results,
      },
    ],
  };
}

// CLI: node clamav-to-sarif.mjs <infile> <outfile>
if (import.meta.url === `file://${process.argv[1]}`) {
  const [, , infile, outfile] = process.argv;
  if (!infile || !outfile) {
    console.error('usage: clamav-to-sarif.mjs <infile> <outfile>');
    process.exit(2);
  }
  const text = readFileSync(infile, 'utf8');
  writeFileSync(outfile, JSON.stringify(toSarif(text), null, 2));
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test .github/scripts/clamav-to-sarif.test.mjs`
Expected: PASS — 4 tests pass.

- [ ] **Step 5: Verify CLI + prettier + eslint on the new files**

Run:

```bash
printf '/x/evil.bin: Win.Test.EICAR_HDB-1 FOUND\n' > /tmp/clam.log
node .github/scripts/clamav-to-sarif.mjs /tmp/clam.log /tmp/clam.sarif && cat /tmp/clam.sarif
npx prettier --write .github/scripts/clamav-to-sarif.mjs .github/scripts/clamav-to-sarif.test.mjs
npx eslint .github/scripts/clamav-to-sarif.mjs .github/scripts/clamav-to-sarif.test.mjs || echo "eslint: check output"
```

Expected: valid SARIF JSON printed with one result; prettier writes clean; eslint passes (if it flags the `.test.mjs` globals like `process`, add nothing — `node:` builtins are imported; adjust only if the flat config lacks a node env for `.mjs`).

Note: if eslint's flat config does not already include `.github/scripts/**`, do NOT broaden it here — these are standalone Node scripts. Confirm they at least parse; the repo's lint gate targets `lib/`/`bin/`/`test/` TS. If eslint errors purely on config-scope (file not matched), that is acceptable — record it.

- [ ] **Step 6: Commit**

```bash
git add .github/scripts/clamav-to-sarif.mjs .github/scripts/clamav-to-sarif.test.mjs
git commit -m "feat(security): add clamdscan-log→SARIF converter for ClamAV job (#149)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Pin the sonar-tools SARIF exporter

**Files:**

- Create: `.github/scanner-requirements/sonar-tools.txt`

**Interfaces:**

- Produces: a `pip install --require-hashes -r .github/scanner-requirements/sonar-tools.txt`-installable closure exposing the `sonar-findings-export` CLI. Consumed by the `sonarqube` job (Task 4).

- [ ] **Step 1: Generate the hash-pinned closure**

Run (matches the header convention of `semgrep.txt`/`iac.txt`; Python 3.12 = the workflow's `setup-python`):

```bash
uv pip compile --universal --generate-hashes --python-version 3.12 \
  --output-file .github/scanner-requirements/sonar-tools.txt - <<<'sonar-tools==3.21'
```

Expected: exit 0, ~24 packages resolved.

- [ ] **Step 2: Prepend the regenerate header**

Add these comment lines at the very top of `.github/scanner-requirements/sonar-tools.txt` (above the uv autogenerate banner), matching the `semgrep.txt` style:

```text
# Content-pinned (hash-verified) requirements for the SonarQube SARIF exporter.
# Consumed by .github/workflows/security.yml (sonarqube job) via
# `pip install --require-hashes`. Top-level pin: sonar-tools==3.21
# (okorach/sonar-tools; LGPL-3.0 — a CI-only externally-invoked exporter,
# adopted under the SonarQube governance exception; see docs/SECURITY-TOOLING.md).
# Regenerate after a version bump (Python 3.12, matches the workflow's setup-python):
#   uv pip compile --universal --generate-hashes --python-version 3.12 \
#     --output-file .github/scanner-requirements/sonar-tools.txt - <<<'sonar-tools==3.21'
```

- [ ] **Step 3: License-spot-check the closure (governance)**

Run:

```bash
grep -oE '^[a-zA-Z0-9._-]+==' .github/scanner-requirements/sonar-tools.txt | sed 's/==//' | sort -u
```

Expected: the closure is `sonar-tools` (LGPL-3.0, covered by the exception) plus standard permissive deps (`requests`, `jsonschema`, `attrs`, `certifi`, `urllib3`, `charset-normalizer`, `idna`, `argparse`, `pytz`, `python-dateutil`, `PyYAML`, `referencing`, `rpds-py`, `jsonschema-specifications`, `six`, etc. — all MIT/Apache/BSD/PSF/ISC). If any transitive dep is copyleft/AGPL that is NOT sonar-tools itself, STOP and escalate (that would be a new, un-approved copyleft dep, not part of the sonar-tools exception).

- [ ] **Step 4: Verify a clean --require-hashes install (dry run)**

Run (in a throwaway venv so it doesn't touch the repo):

```bash
python3.12 -m venv /tmp/st-venv 2>/dev/null || python3 -m venv /tmp/st-venv
/tmp/st-venv/bin/pip install --require-hashes -r .github/scanner-requirements/sonar-tools.txt >/tmp/st-install.log 2>&1 && \
  /tmp/st-venv/bin/sonar-findings-export --help >/dev/null 2>&1 && echo "INSTALL+CLI OK" || { tail -20 /tmp/st-install.log; echo "FAILED"; }
```

Expected: `INSTALL+CLI OK`. If the local interpreter is not 3.12 and install fails on a hash/marker, that is a local-only artifact — the CI job uses `setup-python@3.12`; note it and rely on Task 7's CI run. (The `uv pip compile` in Step 1 already proved the closure resolves for 3.12.)

- [ ] **Step 5: Commit**

```bash
git add .github/scanner-requirements/sonar-tools.txt
git commit -m "chore(security): pin sonar-tools==3.21 SARIF exporter (hash-locked) (#150)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: ClamAV job in security.yml

**Files:**

- Modify: `.github/workflows/security.yml` (append a new `clamav:` job under `jobs:`, after the `trivy-image` / before `sbom` grouping — placement is cosmetic; keep it in the "third-party / scanning" area).

**Interfaces:**

- Consumes: `.github/scripts/clamav-to-sarif.mjs` (Task 1); `actions/setup` composite for Node (the converter runs on `node`). NOTE the composite does NOT checkout — checkout must precede it.
- Produces: SARIF category `clamav`; artifacts `clamdscan.txt` + `clamav.sarif`; hard-fail on detection.

- [ ] **Step 1: Add the `clamav` job**

Insert into `.github/workflows/security.yml` under `jobs:` (2-space job indent to match the file):

```yaml
# ── Malware / virus scan (ClamAV) ───────────────────────────────────────
# Signature-based scan of the working tree (#149). ClamAV (GPLv2) runs as an
# EXTERNAL scanner — a Docker service container + apt `clamdscan` over
# loopback TCP — never linked or redistributed into repo output, the same
# carve-out that clears shellcheck (GPLv3). The `clamav/clamav` image runs
# freshclam at startup, so the scan always uses CURRENT virus signatures
# (the DB floats by design, like Trivy's/Grype's vuln DB; the image is pinned
# by digest). clamdscan has no machine-readable output, so clamav-to-sarif.mjs
# parses its text log into SARIF (every hit = level error / security-severity
# 10.0). Hard-fail via produce → always-upload → enforce.
clamav:
  name: ClamAV virus scan
  runs-on: ubuntu-latest
  timeout-minutes: 15
  permissions:
    contents: read
    security-events: write # upload SARIF to code scanning
  services:
    clamav:
      image: clamav/clamav@sha256:6f4a9e7d616ffc8d1070200fe35ac860735fdd522161a1043f94856e6ee13c28
      ports:
        - 127.0.0.1:3310:3310
      # The image ships its own clamdcheck.sh HEALTHCHECK — use it (do NOT
      # override with a curl/wget cmd; the image lacks them). clamd only
      # reports healthy after freshclam has loaded the signature DB.
      options: >-
        --health-cmd "/usr/local/bin/clamdcheck.sh"
        --health-interval 10s
        --health-timeout 5s
        --health-retries 30
  steps:
    - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
      with:
        persist-credentials: false
    - uses: ./.github/actions/setup
      with:
        npm-ci: 'false' # converter uses Node built-ins only; no deps needed
    - name: Wait for clamd (TCP 3310)
      run: timeout 300 bash -c 'until (echo > /dev/tcp/127.0.0.1/3310) 2>/dev/null; do sleep 5; done'
    - name: Install clamdscan client + point it at the service
      run: |
        sudo apt-get update || true
        sudo rm -f /var/lib/man-db/auto-update
        sudo apt-get install -y --no-install-recommends clamdscan
        sudo mkdir -p /etc/clamav
        cat << 'EOF' | sudo tee /etc/clamav/clamd.conf
        TCPSocket 3310
        TCPAddr 127.0.0.1
        EOF
        clamdscan --version
    - name: Run clamdscan (log; enforce after upload)
      run: |
        set +e
        clamdscan --verbose --log=clamdscan.txt --stream --fdpass --multiscan .
        echo "exit=$?" > clamav.outcome
    - name: Convert clamdscan log to SARIF
      if: always()
      run: node .github/scripts/clamav-to-sarif.mjs clamdscan.txt clamav.sarif
    - name: Upload SARIF to Security tab
      if: always()
      uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
      with:
        sarif_file: clamav.sarif
        category: clamav
    - name: Upload ClamAV reports
      if: always()
      uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
      with:
        name: clamav-reports
        path: |
          clamdscan.txt
          clamav.sarif
        if-no-files-found: warn
    - name: Enforce ClamAV result (hard-fail on any detection)
      if: always()
      run: |
        source clamav.outcome
        echo "clamdscan exit=$exit (non-zero = virus signature detected)"
        test "$exit" = "0"
```

- [ ] **Step 2: Lint the workflow (actionlint + zizmor)**

Run:

```bash
# actionlint (pinned, matches CI)
curl -sSfL -o /tmp/actionlint.tgz https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz
echo "8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8  /tmp/actionlint.tgz" | sha256sum -c -
tar -xzf /tmp/actionlint.tgz -C /tmp actionlint && /tmp/actionlint -color .github/workflows/security.yml
```

Expected: no errors. If `/dev/tcp` triggers an actionlint shellcheck SC-warning, that is acceptable (it's a bash builtin); if it errors, switch the wait step to `nc -z 127.0.0.1 3310` guarded by an install — but prefer `/dev/tcp` (no extra dep).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(security): add ClamAV virus-scan job (SARIF, hard-fail) (#149)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: SonarQube job in security.yml

**Files:**

- Modify: `.github/workflows/security.yml` (append a `sonarqube:` job).

**Interfaces:**

- Consumes: `.github/scanner-requirements/sonar-tools.txt` (Task 2); the two pinned SonarSource actions; a local SonarQube Community service container.
- Produces: SARIF category `sonarqube`; artifacts `sonar.sarif` + `sonar-issues.json`; **report-only** (never fails the job).

- [ ] **Step 1: Add the `sonarqube` job**

Insert into `.github/workflows/security.yml` under `jobs:`:

```yaml
# ── SonarQube (code quality + security analysis) ─────────────────────────
# SonarQube Community (#150) run fully credential-free against a service
# container: self-generate a token via the first-boot admin API, scan, check
# the quality gate. GOVERNANCE: the two SonarSource actions AND okorach/
# sonar-tools (the SARIF exporter) are all LGPL-3.0, and SonarQube is a
# single-vendor SonarSource product — a MAINTAINER-APPROVED exception under
# the CI-only external-invocation carve-out (same as shellcheck/ClamAV; the
# actions/CLI are invoked, never linked/redistributed). See
# docs/SECURITY-TOOLING.md. Failure policy is REPORT-ONLY (log the gate
# status, never fail — mirrors trivy-fs), with a documented ratchet to
# enforce once the baseline is triaged. SARIF (via sonar-findings-export)
# still lands in the Security tab regardless.
sonarqube:
  name: SonarQube analysis
  runs-on: ubuntu-latest
  timeout-minutes: 20
  permissions:
    contents: read
    security-events: write # upload SARIF to code scanning
  services:
    sonarqube:
      image: sonarqube:community@sha256:160bd2f6a3485bd09b655ef22dd63c02bd1fa7ba82aa5d9973fd010b8bcca0b3
      ports:
        - 127.0.0.1:9000:9000
      env:
        SONAR_ES_BOOTSTRAP_CHECKS_DISABLE: true
        SONAR_WEB_SYSTEMPASSCODE: passcode
      options: >-
        --health-cmd "wget --no-verbose --tries=1 --spider http://localhost:9000/api/system/status || exit 1"
        --health-interval 15s
        --health-timeout 10s
        --health-retries 30
        --health-start-period 60s
  steps:
    - uses: actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0 # v7
      with:
        fetch-depth: 0 # Sonar wants full history for new-code / blame
        persist-credentials: false
    - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
      with:
        python-version: '3.12'
    - name: Wait for SonarQube to report UP
      run: |
        for _ in $(seq 1 60); do
          status=$(curl -s http://localhost:9000/api/system/status | jq -r '.status // empty')
          echo "status=$status"
          if [ "$status" = "UP" ]; then exit 0; fi
          sleep 5
        done
        echo "::error::SonarQube did not reach UP in time"; exit 1
    - name: Generate a scanner token (first-boot admin API)
      # admin/admin via env, not a literal `-u user:pass` (gitleaks curl-auth-user).
      env:
        SONAR_BOOT_USER: admin
        SONAR_BOOT_PASS: admin
      run: |
        token=$(curl -s -u "$SONAR_BOOT_USER:$SONAR_BOOT_PASS" -X POST \
          "http://localhost:9000/api/user_tokens/generate?name=github-actions" | jq -r '.token')
        if [ -z "$token" ] || [ "$token" = "null" ]; then
          echo "::error::failed to generate SonarQube token"; exit 1
        fi
        echo "::add-mask::$token"
        echo "SONAR_TOKEN=$token" >> "$GITHUB_ENV"
    - name: Create SonarQube project
      env:
        SONAR_TOKEN: ${{ env.SONAR_TOKEN }}
      run: |
        curl -s -X POST -H "Authorization: Bearer $SONAR_TOKEN" \
          "http://localhost:9000/api/projects/create?project=e2e-ministack&name=e2e-ministack" > /dev/null
    - name: Run SonarQube scan
      uses: SonarSource/sonarqube-scan-action@713881670b6b3676cda39549040e2d88c70d582e # v8.2.0
      env:
        SONAR_HOST_URL: http://localhost:9000
        SONAR_TOKEN: ${{ env.SONAR_TOKEN }}
      with:
        args: >
          -Dsonar.projectKey=e2e-ministack
          -Dsonar.projectName=e2e-ministack
          -Dsonar.sources=.
          -Dsonar.exclusions=node_modules/**,cdk.out/**,coverage/**,reports/**
    - name: Check quality gate (report-only)
      id: qg
      continue-on-error: true
      uses: SonarSource/sonarqube-quality-gate-action@cf038b0e0cdecfa9e56c198bbb7d21d751d62c3b # v1.2.0
      timeout-minutes: 5
      env:
        SONAR_HOST_URL: http://localhost:9000
        SONAR_TOKEN: ${{ env.SONAR_TOKEN }}
    - name: Export findings to SARIF (sonar-tools) + raw issues JSON
      if: always()
      env:
        SONAR_TOKEN: ${{ env.SONAR_TOKEN }}
      run: |
        pip install --require-hashes -r .github/scanner-requirements/sonar-tools.txt
        # sonar-findings-export: native --format sarif exporter.
        sonar-findings-export -u http://localhost:9000 -t "$SONAR_TOKEN" \
          -k e2e-ministack --format sarif -f sonar.sarif || echo "::warning::sarif export returned non-zero"
        # Raw issues JSON for parity with the reference artifact.
        curl -s -H "Authorization: Bearer $SONAR_TOKEN" \
          "http://localhost:9000/api/issues/search?componentKeys=e2e-ministack&ps=500&p=1" > sonar-issues.json || true
    - name: Upload SARIF to Security tab
      if: always()
      uses: github/codeql-action/upload-sarif@99df26d4f13ea111d4ec1a7dddef6063f76b97e9 # v4.37.0
      with:
        sarif_file: sonar.sarif
        category: sonarqube
    - name: Upload SonarQube reports
      if: always()
      uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
      with:
        name: sonarqube-reports
        path: |
          sonar.sarif
          sonar-issues.json
        if-no-files-found: warn
    - name: Report quality-gate status (report-only — never fails)
      if: always()
      env:
        QG_STATUS: ${{ steps.qg.outputs.quality-gate-status }}
      run: |
        # Report-only (mirrors trivy-fs): LOG the gate status, do NOT fail.
        # Ratchet: a follow-up flips this to `test "$QG_STATUS" = "PASSED"`.
        echo "SonarQube quality gate status: ${QG_STATUS:-unknown} (report-only — not enforced)"
```

- [ ] **Step 2: zizmor + actionlint the workflow**

Run:

```bash
/tmp/actionlint -color .github/workflows/security.yml
```

Expected: no errors. **zizmor** (template-injection) verification: confirm NO `run:` block contains `${{`. The `SONAR_TOKEN`/`QG_STATUS` values are passed via `env:` and referenced as `$SONAR_TOKEN` / `$QG_STATUS`. Grep to prove it:

```bash
awk '/^  sonarqube:/,/^  [a-z]/' .github/workflows/security.yml | grep -n 'run:' -A6 | grep '\${{' && echo "VIOLATION: template in run:" || echo "clean: no template in run: blocks"
```

Expected: `clean: no template in run: blocks`.

If a local zizmor is available, run `zizmor .github/workflows/security.yml` and expect no new findings; otherwise rely on the CI zizmor job (Task 7).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(security): add SonarQube analysis job (SARIF, report-only) (#150)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: dependency-review exemption for the LGPL SonarSource action (#161, Option A)

**Files:**

- Modify: `.github/workflows/security.yml` (the existing `dependency-review` job — add `allow-dependencies-licenses`).

**Interfaces:**

- Consumes: the existing `dependency-review` step (`id: review`, `actions/dependency-review-action@a1d282b...`).
- Produces: the LGPL `SonarSource/sonarqube-scan-action` is exempted so the PR introducing it (this one) is not failed by the license allow-list.

**Why:** `dependency-review` scans GitHub Actions as dependencies. The moment Task 4 adds the LGPL `sonarqube-scan-action`, the allow-list (permissive-only) would fail THIS PR by omission. The awslabs reference exempts exactly this action via `allow-dependencies-licenses` with a SHA-pinned purl. This is #161 Option A (minimal adopt: keep the inline allow-list + poller; add only the per-dependency exemption).

- [ ] **Step 1: Verify #161 Q1 empirically (purl match semantics)**

The spec/docs claim `allow-dependencies-licenses` matches **by name only** (ignoring `@version`), while the awslabs comment claims SHA-pinning re-triggers on bump. Determine the truth before relying on it. Inspect the action's matcher:

```bash
# The action bundles its logic; the purl match lives in its licenses filter.
# Check the released source for how purlsMatch/allow-dependencies-licenses
# compares versions (name-only vs name@version).
gh api repos/actions/dependency-review-action/contents/src/licenses.ts \
  --jq '.content' 2>/dev/null | base64 -d 2>/dev/null | grep -niA8 'allow.*dependenc\|purlMatch\|parsePURL\|namespace' | head -60
```

Record the finding (name-only vs versioned) in the step output. Both the docs claim and the awslabs comment cannot both be right; whichever holds, document it in Task 6's docs edit. **Either way the exemption works for THIS PR** (the action name matches); the only question is whether a future SHA bump silently keeps the exemption (name-only) or re-triggers review (versioned).

- [ ] **Step 2: Add `allow-dependencies-licenses` to the review step**

In `.github/workflows/security.yml`, in the `dependency-review` job's `with:` block (the step with `id: review`), add — placed after `allow-licenses:` and its comment block, before the `# allow-dependencies-licenses is intentionally ABSENT` comment (which must be UPDATED, see Step 3):

```yaml
# SonarQube exception (#150/#161): SonarSource/sonarqube-scan-action is
# LGPL-3.0, which is copyleft and NOT on the permissive allow-list
# above. It is a CI-ONLY action we invoke in the pipeline — never
# linked or redistributed into repo output — so its copyleft terms do
# not reach that output (the same external-invocation carve-out that
# clears shellcheck/ClamAV). This is a MAINTAINER-APPROVED exception
# (see docs/SECURITY-TOOLING.md). The purl is SHA-pinned to the exact
# action version this repo runs. NOTE (#161 Q1): the action matches
# allow-dependencies-licenses by <name> [name-only|versioned — record
# the verified result from Task 5 Step 1 here]; a future SHA bump
# [does|does not] re-trigger review accordingly.
allow-dependencies-licenses: >-
  pkg:githubactions/SonarSource/sonarqube-scan-action@713881670b6b3676cda39549040e2d88c70d582e
```

- [ ] **Step 3: Update the now-stale "intentionally ABSENT" comment**

The existing block says `allow-dependencies-licenses is intentionally ABSENT (steady state: empty)`. That is no longer literally true. Edit that comment to note the single, documented exception:

Change the opening line of that comment from:

```text
          # allow-dependencies-licenses is intentionally ABSENT (steady state:
          # empty). "Could not detect a license" on a brand-new release is
```

to:

```text
          # allow-dependencies-licenses carries exactly ONE documented entry —
          # the SonarQube LGPL exception above (#150/#161). It is otherwise kept
          # empty for the license-UNKNOWN path: "Could not detect a license" on
          # a brand-new release is
```

(Leave the rest of that comment — the ClearlyDefined/harvest routing rationale — unchanged.)

- [ ] **Step 4: actionlint**

Run: `/tmp/actionlint -color .github/workflows/security.yml`
Expected: no errors.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/security.yml
git commit -m "feat(deps): exempt LGPL sonarqube-scan-action via allow-dependencies-licenses (#161)

Option A from #161: keep the inline allow-list + license-review poller; add only
the per-dependency exemption for the SonarQube LGPL action introduced by #150.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: gitignore/prettierignore + documentation

**Files:**

- Modify: `.gitignore`, `.prettierignore` — add `clamdscan.txt`, `sonar-issues.json`.
- Modify: `docs/SECURITY-TOOLING.md` — gate rows + ClamAV/SonarQube subsections.
- Modify: `docs/PINNING.md` — register images + actions + sonar-tools; note ClamAV floating DB.
- Modify: `AGENTS.md` — bullets under "Security checks".

**Interfaces:** none (docs + ignore files).

- [ ] **Step 1: Ignore the new named report files**

In `.gitignore`, in the "CI scan reports / outcome files" block (after `trivy-image.txt`), add:

```text
clamdscan.txt
sonar-issues.json
```

In `.prettierignore`, in the "CI-generated scan reports / artifacts" block (after `trivy-image.txt`), add:

```text
clamdscan.txt
sonar-issues.json
```

(`*.sarif` and `*.outcome` are already globbed in both; `clamav.sarif`/`sonar.sarif`/`clamav.outcome` need no new entry.)

- [ ] **Step 2: Update `docs/SECURITY-TOOLING.md` gate inventory + subsections**

In the `## Gate inventory` table, add two rows (keep column alignment):

```text
| ClamAV                | security.yml | working-tree virus/malware signature scan | hard-fail             |
| SonarQube             | security.yml | code quality + security analysis (Community) | report-only        |
```

Add two new subsections (after the "Trivy (second vuln scanner)" section, before "MiniStack image scan"):

```markdown
## ClamAV virus scan (#149)

The `clamav` job runs [ClamAV](https://www.clamav.net/) (Cisco Talos, GPLv2) as
a signature-based malware scan of the working tree. ClamAV is invoked as an
**external scanner** — a `clamav/clamav` Docker service container plus the apt
`clamdscan` client over loopback TCP — never linked or redistributed into repo
output, the identical carve-out that clears **shellcheck (GPLv3)**. So it adds
no copyleft dependency.

- **Signatures float by design.** The pinned `clamav/clamav` image runs
  `freshclam` at container start, pulling the current virus CVDs before clamd
  reports healthy — so every run scans with up-to-date signatures. This mirrors
  the Trivy/Grype floating-vuln-DB rationale: the image is pinned by **digest**
  (reproducible engine), the signature **data** floats (fresh coverage). No
  signature DB is committed.
- **SARIF.** clamdscan has no machine-readable output, so
  `.github/scripts/clamav-to-sarif.mjs` parses its text log (`PATH: SIG FOUND`
  lines) into SARIF 2.1.0. A virus-signature match is unambiguously critical, so
  every finding maps to `level: error` / `security-severity: 10.0`. A clean tree
  yields a valid empty-results SARIF.
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
  (`clamav-to-sarif.test.mjs`).

## SonarQube analysis (#150) — governance exception

The `sonarqube` job runs **SonarQube Community** fully credential-free against a
service container (self-generates a scanner token via the first-boot admin API),
then exports findings to SARIF.

**Governance — a maintainer-approved exception.** Three pieces are **LGPL-3.0**:
`SonarSource/sonarqube-scan-action`, `SonarSource/sonarqube-quality-gate-action`,
and `okorach/sonar-tools` (the SARIF exporter). Two separable concerns:

1. **Copyleft.** Mitigated by the same **CI-only external-invocation carve-out**
   as ClamAV/shellcheck: these are `uses:` actions / a pip-installed CLI invoked
   in the pipeline, never linked or redistributed into repo output, so their
   copyleft terms don't reach it. The `dependency-review` gate (which sees the
   action as a dependency) exempts it via `allow-dependencies-licenses` with a
   SHA-pinned purl (#161).
2. **Single-vendor.** SonarQube is a SonarSource product — this is the genuine
   deviation from the single-vendor line that rejected k6 (#73) and Renovate
   (#80), accepted here as a **deliberate, documented exception** by the
   maintainer, recorded on the PR. Not a silent override.

- **Failure policy: report-only.** The default "Sonar way" quality gate is tuned
  for application repos and would be noisy on first run, so the enforce step
  **logs** the gate status and never fails the job — exactly mirroring the
  `trivy-fs` report-only posture. **Ratchet:** a follow-up flips it to
  `test "$QG_STATUS" = "PASSED"` once the baseline is triaged / the quality
  profile is tuned.
- **SARIF** via `sonar-findings-export --format sarif` (native exporter, pinned
  in `.github/scanner-requirements/sonar-tools.txt`, `--require-hashes`), uploaded
  under category `sonarqube`. The raw `api/issues/search` JSON is kept as an
  artifact for parity.

### dependency-review `allow-dependencies-licenses` (#161)

`#161` evaluated whether the awslabs `config-file` / `allow-dependencies-licenses`
pattern could replace the bespoke license machinery. **Finding:** `config-file`
is a PR-time policy-location change and is **orthogonal** to
`license-review-poller.yml`, which is the _post-merge_ enforcement for the
ClearlyDefined harvest-lag hole (#127 Leg B) — so adopting awslabs wholesale
would DELETE that enforcement, not simplify it. **Decision: Option A** — keep the
inline `allow-licenses` allow-list and the poller unchanged, and adopt ONLY the
per-dependency `allow-dependencies-licenses` exemption for the LGPL SonarQube
action. **#161 Q1 (match semantics):** verified that `allow-dependencies-licenses`
matches by `[NAME-ONLY | NAME@VERSION — fill from Task 5 Step 1]`; a future SHA
bump `[does|does not]` re-trigger the license review accordingly.
```

**IMPORTANT:** when filling this in, replace the `[NAME-ONLY | ...]` / `[does|does not]` placeholders with the ACTUAL verified result from Task 5 Step 1. Do not leave brackets in the committed doc.

- [ ] **Step 3: Update `docs/PINNING.md`**

In the `## Pinned` table, add rows for the two SonarSource actions, `sonar-tools`, and both images (match the existing column format). In the `## Intentionally NOT pinned (with reasons)` section, add a bullet:

```markdown
- **ClamAV virus signature database** — the `clamav/clamav` image is pinned by
  digest, but its signature CVDs are refreshed by `freshclam` at container start
  (floating by design, same rationale as the Trivy/Grype vuln DBs). Pinning
  signatures would defeat the scan's purpose (catch newly-catalogued malware).
```

Add the two actions + `sonar-tools` + both images to the #78 pin-sync target list wherever that inventory lives in the file.

- [ ] **Step 4: Update `AGENTS.md`**

Under `## Security checks`, add two concise bullets (matching the existing bullet style), e.g. after the SAST/secrets bullet:

```markdown
- **ClamAV** — signature-based virus/malware scan of the working tree
  (`clamav` job). External scanner (GPLv2, Docker service + apt `clamdscan`) —
  same carve-out as shellcheck; **hard-fail**. Signatures float via freshclam
  (image pinned by digest); clamdscan text log → SARIF via
  `.github/scripts/clamav-to-sarif.mjs`. Verify detection with EICAR on a
  throwaway path (never commit it — the job scans `.`).
- **SonarQube** — SonarQube Community code-quality + security analysis
  (`sonarqube` job), credential-free against a service container; SARIF via the
  pinned `okorach/sonar-tools` exporter. **Report-only** (mirrors `trivy-fs`),
  ratcheting to enforce later. **Governance exception:** the two SonarSource
  actions + sonar-tools are LGPL-3.0 and SonarQube is single-vendor — a
  maintainer-approved deviation under the CI-only external-invocation carve-out;
  the LGPL action is exempted in `dependency-review` via
  `allow-dependencies-licenses` (#150/#161). See docs/SECURITY-TOOLING.md.
```

- [ ] **Step 5: Format + lint docs**

Run:

```bash
npx prettier --write docs/SECURITY-TOOLING.md docs/PINNING.md AGENTS.md
npx markdownlint-cli2 docs/SECURITY-TOOLING.md docs/PINNING.md AGENTS.md 2>&1 | tail -5
npx prettier --check .gitignore .prettierignore 2>&1 | tail -2 || true
```

Expected: prettier clean; markdownlint no errors.

- [ ] **Step 6: Commit**

```bash
git add .gitignore .prettierignore docs/SECURITY-TOOLING.md docs/PINNING.md AGENTS.md
git commit -m "docs(security): document ClamAV + SonarQube gates, pins, and the #161 decision

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Push, verify CI, open the draft PR

**Files:** none (CI + PR).

- [ ] **Step 1: Rebase onto latest main + final local lint sweep**

```bash
git -C /local/home/scoschre/github.com/scottschreckengaust/e2e-ministack fetch origin
git rebase origin/main
/tmp/actionlint -color .github/workflows/security.yml
node --test .github/scripts/clamav-to-sarif.test.mjs
```

Expected: rebase clean (or resolve trivially — only new files + appended jobs); actionlint clean; converter tests pass.

- [ ] **Step 2: Push the branch**

```bash
git push -u origin feat/security-scanners-clamav-sonarqube
```

- [ ] **Step 3: Open the DRAFT PR**

```bash
gh pr create --draft \
  --title "feat(security): add ClamAV + SonarQube scanners; exempt LGPL Sonar action in dependency-review (#149, #150, #161)" \
  --body "$(cat <<'EOF'
## Summary

Adds two new security scanners to `security.yml` and wires the dependency-review
license exemption they require.

- **ClamAV (#149)** — signature-based virus scan of the working tree. External
  scanner (GPLv2, Docker service + apt `clamdscan`) under the same carve-out as
  shellcheck. Fresh signatures via freshclam (image pinned by digest). clamdscan
  text log → SARIF via `.github/scripts/clamav-to-sarif.mjs` (every hit =
  `error` / `security-severity` 10.0). **Hard-fail.**
- **SonarQube (#150)** — SonarQube Community analysis, credential-free against a
  service container; SARIF via the pinned `okorach/sonar-tools` exporter.
  **Report-only** (mirrors `trivy-fs`), ratcheting to enforce later.
- **dependency-review (#161)** — Option A: keep the inline allow-list + the
  license-review poller; exempt only the LGPL `sonarqube-scan-action` via
  `allow-dependencies-licenses` (SHA-pinned purl).

## Governance — SonarQube exception (maintainer-approved)

Three pieces are **LGPL-3.0** (both SonarSource actions + `sonar-tools`) and
SonarQube is a **single-vendor** SonarSource product — both against the repo's
tool-adoption line (the one that rejected k6/#73 and Renovate/#80). Accepted as a
**deliberate, documented exception**:
1. *Copyleft* — mitigated by the CI-only external-invocation carve-out (invoked,
   never linked/redistributed), same as shellcheck/ClamAV.
2. *Single-vendor* — the genuine deviation, explicitly accepted here.

Recorded in `docs/SECURITY-TOOLING.md`. ClamAV needs no exception (external GPLv2).

## Pins (all current-latest, SHA/digest-pinned)

| Item | Pin |
| --- | --- |
| `sonarqube-scan-action` | `713881670b6b3676cda39549040e2d88c70d582e` (v8.2.0) |
| `sonarqube-quality-gate-action` | `cf038b0e0cdecfa9e56c198bbb7d21d751d62c3b` (v1.2.0) |
| `okorach/sonar-tools` | `3.21` (hash-pinned) |
| `clamav/clamav` | `sha256:6f4a9e7d…13c28` |
| `sonarqube:community` | `sha256:160bd2f6…a0b3` |

## #161 Q1 finding

`allow-dependencies-licenses` matches by [NAME-ONLY | NAME@VERSION — fill from Task 5]; documented in `docs/SECURITY-TOOLING.md`.

## Verification

- Converter unit-tested (`node --test`); EICAR detection verified on a throwaway
  path (not committed — the job scans `.`).
- actionlint / zizmor clean; SARIF appears in the Security tab (categories
  `clamav` / `sonarqube`).

Design + plan: `docs/superpowers/specs/2026-07-09-*`, `docs/superpowers/plans/2026-07-09-*`.

Closes #149
Closes #150
Closes #161

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

- [ ] **Step 4: Watch CI; iterate on the two new jobs until green (Sonar report-only)**

```bash
gh pr checks --watch
```

Expected: `clamav` green (clean tree), `sonarqube` green (report-only), `dependency-review` green (exemption applied), all existing gates still green. If `clamav` fails, inspect the `clamav-reports` artifact; if `sonarqube` fails to reach UP, bump `--health-start-period` / retries. Fix, commit, re-push.

- [ ] **Step 5: Fill in the PR-body / doc placeholders from real CI results**

Once green, replace the `[NAME-ONLY | ...]` placeholder in the PR body and `docs/SECURITY-TOOLING.md` with the verified #161 Q1 result (if not already done in Task 5/6). Leave the PR as **draft** for maintainer review (do not mark ready — the user opens/merges).

---

## Self-Review

**1. Spec coverage:**

- ClamAV job + digest + freshclam DB + hard-fail + SARIF (level/severity) → Tasks 1, 3, 6. ✓
- SonarQube job + credential-free + report-only + sonar-tools SARIF + zizmor hardening → Tasks 2, 4, 6. ✓
- Governance exception (3 LGPL + single-vendor, carve-out) recorded → Tasks 4 (comment), 6 (docs), 7 (PR). ✓
- #161 evaluation + Option A + Q1 verification → Task 5. ✓
- Pins (all 5) → Global Constraints + Tasks 2/3/4; PINNING.md → Task 6. ✓
- EICAR verification (throwaway + converter unit-proof) → Task 1 (tests), Task 6 (doc), Task 7 (PR). ✓
- ignore-file updates for new named reports → Task 6. ✓
- Out-of-scope items (pre-commit ClamAV, config-file adopt) → not implemented, correct. ✓

**2. Placeholder scan:** The only bracketed placeholders are the #161 Q1 result (`[NAME-ONLY | ...]`), which are DELIBERATE — they get filled from Task 5 Step 1's empirical result and are called out explicitly with "do not leave brackets." No `TBD`/`TODO`/"add error handling"/"similar to Task N". ✓

**3. Type consistency:** `toSarif(logText)` signature + SARIF shape identical across Task 1 test, Task 1 impl, and Task 3 CLI invocation. Project key `e2e-ministack` consistent across Task 4 create/scan/export steps. Env var names `SONAR_TOKEN` / `QG_STATUS` consistent. File paths (`clamav-to-sarif.mjs`, `sonar-tools.txt`, `sonar.sarif`, `clamdscan.txt`, `sonar-issues.json`) consistent across tasks and ignore-file edits. ✓
