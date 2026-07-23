#!/usr/bin/env bash
# Local ↔ CI gate-parity entrypoint (#185).
#
# ONE command that runs every REPRODUCIBLE CI gate locally, in CI order, in
# CI-parity config (severity floors, VEX feeds, engine pins), so a fully-
# sandboxed agent can catch a new CVE / missing VEX record / gate failure BEFORE
# push instead of via a CI round-trip. Invoked as `npm run verify:all`.
#
# GATE TIERS (see docs/SECURITY-TOOLING.md § "Local CI parity for an agent
# sandbox" for the full classification + rationale):
#   * trivially-local  — no network/docker; always run.
#   * heavy-but-local  — needs docker or a service container (MiniStack E2E,
#                        ClamAV, SonarQube); OPT-IN / auto-skip-with-notice when
#                        docker/services aren't up (set RUN_DOCKER_GATES=1 to
#                        attempt them). This script does NOT itself start those
#                        services — it runs the reproducible SCANNER parity and
#                        reports which docker gates were skipped and how to run
#                        them.
#   * CI-only          — no faithful local twin (CodeQL analyzer bundle,
#                        dependency-review's PR dep-diff) or reporting-only side
#                        effects (octocov PR comment, SBOM/SARIF upload). NOT run
#                        here by design; listed at the end so the gap is explicit.
#
# HONEST RESIDUAL: the grype/trivy vuln DB and ClamAV signatures FLOAT by design
# (#183) — a CVE disclosed after your last DB refresh can still red CI. So this
# reduces round-trips to NEAR-zero, not exactly zero.
#
# TOOLS: the binary scanners (grype/trivy/osv-scanner/shellcheck) come from
# `mise install` at the CI-pinned engine versions (mise.toml). The pip scanners
# (cfn-lint/checkov/semgrep) install from the SAME hash-pinned closures CI uses
# (.github/scanner-requirements/) into an ephemeral venv, so there is no second
# version source for them.
#
# Honors the repo's observability convention: never silently skip — every gate
# echoes RAN / SKIPPED (+ why). Exits non-zero if ANY run gate failed.

# The gate helpers below are invoked INDIRECTLY (via `run_gate "$name" <fn>` or a
# conditional call), which shellcheck's static analysis can't see — silence its
# file-wide "function never invoked" info rather than tagging each definition.
# shellcheck disable=SC2329
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

# ── Result accumulators ─────────────────────────────────────────────────────
declare -a PASSED=() FAILED=() SKIPPED=()
# Transient scan outputs go under a mktemp WORK_DIR so nothing can leak into the
# tree even if a scan is interrupted (grype's JSON, in particular, is NOT
# gitignored). The pip venv lives here too. All cleaned on exit.
WORK_DIR="$(mktemp -d)"
VENV_DIR="$WORK_DIR/venv"
cleanup() { [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"; }
trap cleanup EXIT

hr() { printf '\n\033[1m── %s ──\033[0m\n' "$1"; }
note_skip() {
  # note_skip <gate> <reason>
  SKIPPED+=("$1 — $2")
  printf '\033[33m⊘ SKIP\033[0m %-28s %s\n' "$1" "$2"
}

# run_gate <name> <command...> — run a gate, record pass/fail, keep going.
run_gate() {
  local name="$1"
  shift
  hr "$name"
  if "$@"; then
    PASSED+=("$name")
    printf '\033[32m✓ PASS\033[0m %s\n' "$name"
  else
    FAILED+=("$name")
    printf '\033[31m✗ FAIL\033[0m %s\n' "$name"
  fi
}

# ── mise binary scanners on PATH (CI-pinned engine versions) ─────────────────
# `mise install` provisions grype/trivy/osv-scanner/shellcheck at the versions in
# mise.toml (== the security.yml engine pins). If mise isn't available, those
# gates auto-skip with a notice rather than silently using a drifting system copy.
MISE_BIN=""
if command -v mise >/dev/null 2>&1; then
  mise install >/dev/null 2>&1 || true
  # Prepend mise shims so `grype`/`trivy`/... resolve to the pinned versions.
  eval "$(mise env 2>/dev/null)" || true
  MISE_BIN="yes"
fi

# have <tool> — true if the tool resolves (via mise or system).
have() { command -v "$1" >/dev/null 2>&1; }

# ── Ephemeral pip venv for the hash-pinned IaC/SAST scanners ─────────────────
# Mirrors CI: cfn-lint/checkov from iac/requirements.txt (--no-deps, matching the
# aiohttp-override closure), semgrep from semgrep/requirements.txt. Installed once,
# reused by the IaC + Semgrep gates below. Skipped (with notice) if python3 is
# absent — those gates then report SKIPPED.
setup_pip_venv() {
  have python3 || { note_skip "pip-venv" "python3 not found — cfn-lint/checkov/semgrep will skip"; return 1; }
  python3 -m venv "$VENV_DIR" >/dev/null 2>&1 || { note_skip "pip-venv" "venv creation failed"; return 1; }
  # shellcheck disable=SC1091
  . "$VENV_DIR/bin/activate"
  pip install --quiet --upgrade pip >/dev/null 2>&1 || true
  return 0
}

PIP_READY=""
setup_pip_venv && PIP_READY="yes"

echo "==============================================================="
echo " verify:all — local ↔ CI gate parity (#185)"
if [[ -n "$MISE_BIN" ]]; then
  echo "   mise scanners: on (grype/trivy/osv/shellcheck at CI-pinned versions)"
else
  echo "   mise scanners: off — grype/trivy/osv-scanner/shellcheck will SKIP"
fi
if [[ -n "$PIP_READY" ]]; then
  echo "   pip scanners : on (cfn-lint/checkov/semgrep from the hashed closures)"
else
  echo "   pip scanners : off — cfn-lint/checkov/semgrep will SKIP"
fi
echo "==============================================================="

# ═════════════════════════ TRIVIALLY-LOCAL GATES ════════════════════════════
# Run in CI order (ci.yml unit job first, then the security.yml scanners).

# —— ci.yml: unit job ——
run_gate "eslint"            npm run --silent lint
run_gate "markdownlint"      npm run --silent lint:md
run_gate "prettier"          npm run --silent format:check
run_gate "mcp-parity"        npm run --silent check:mcp-parity
run_gate "build (tsc)"       npm run --silent build
run_gate "integ-snapshot"    npm run --silent test:integ-snapshot
run_gate "unit tests (100% cov + cdk-nag fast tier)" npm run --silent test:unit
run_gate "fuzz-regression"   npm run --silent test:fuzz-regression
run_gate "cdk-nag synth gate" npm run --silent synth

# —— ci.yml: mutation job ——
run_gate "mutation (Stryker, 0 survivors)" npm run --silent test:mutation

# —— security.yml: npm audit (VEX-aware, JSON-derived) ——
npm_audit_gate() {
  set +e
  local outcome=""
  npm audit --json > npm-audit.json 2>/dev/null
  shopt -s nullglob
  local vex=(.vex/*.openvex.json)
  node .github/scripts/npm-audit-gate.mjs npm-audit.json "$(date -u +%Y-%m-%d)" "${vex[@]}"
  # The gate shim writes npm-audit.outcome (KEY=VALUE, sets `outcome`) and always
  # exits 0 (produce → enforce). shellcheck can't see the sourced assignment.
  # shellcheck disable=SC1091,SC2034
  source npm-audit.outcome
  rm -f npm-audit.json npm-audit.outcome
  test "$outcome" = "success"
}
run_gate "npm audit (VEX-aware)" npm_audit_gate

# —— security.yml: OSV-Scanner (npm lockfile — hard-fail surface only) ——
osv_gate() {
  have osv-scanner || { note_skip "OSV-Scanner" "osv-scanner not on PATH (mise install failed?)"; return 0; }
  osv-scanner scan source --lockfile=package-lock.json
}
if have osv-scanner; then run_gate "OSV-Scanner (npm lockfile)" osv_gate; else note_skip "OSV-Scanner" "osv-scanner not on PATH"; fi

# —— security.yml: Grype FS gate (VEX-aware, JSON-derived, strictest floor) ——
grype_fs_gate() {
  shopt -s nullglob
  local outcome=""
  local vex=(.vex/*.openvex.json)
  local docs json="$WORK_DIR/grype-fs.json"
  docs="$(printf '%s,' "${vex[@]}" | sed 's/,$//')"
  # Match CI (security.yml grype FS job): VEX-fed JSON scan at the strictest floor
  # (grype's severity-cutoff sets only the exit code — the TS gate is the
  # authoritative floor, counting every severity — so we don't pass a cutoff),
  # then the JSON-derived gate. JSON goes under WORK_DIR, not the tree.
  GRYPE_VEX_DOCUMENTS="$docs" grype dir:. --output json --file "$json" -q >/dev/null 2>&1
  node .github/scripts/grype-fs-gate.mjs "$json" "${vex[@]}"
  # The gate shim writes grype-fs.outcome (KEY=VALUE, sets `outcome`, gitignored)
  # and always exits 0. shellcheck can't see the sourced assignment.
  # shellcheck disable=SC1091,SC2034
  source grype-fs.outcome
  rm -f grype-fs.outcome
  test "$outcome" = "success"
}
if have grype; then run_gate "Grype FS (VEX-aware, any severity)" grype_fs_gate; else note_skip "Grype FS" "grype not on PATH (mise install failed?)"; fi

# —— security.yml: Trivy FS (report-only in CI; run + report here too) ——
trivy_fs_gate() {
  # Report-only in CI (trivy-fs); we run it for parity but never fail on it.
  trivy fs . --scanners vuln --quiet || true
  return 0
}
if have trivy; then run_gate "Trivy FS (report-only)" trivy_fs_gate; else note_skip "Trivy FS" "trivy not on PATH"; fi

# —— security.yml: IaC (cfn-lint + checkov) over synthesized cdk.out ——
iac_gate() {
  [[ -n "$PIP_READY" ]] || { note_skip "IaC (cfn-lint+checkov)" "pip venv unavailable"; return 0; }
  # Match CI's hash-pinned closure install (checkov + cfn-lint; --no-deps).
  pip install --quiet --require-hashes --no-deps -r .github/scanner-requirements/iac/requirements.txt >/dev/null 2>&1 \
    || { echo "checkov/cfn-lint install failed"; return 1; }
  [[ -d cdk.out ]] || npm run --silent synth >/dev/null 2>&1
  local cfn=0 ckv=0
  cfn-lint cdk.out/*.template.json --non-zero-exit-code error || cfn=$?
  checkov -d cdk.out --framework cloudformation --compact --quiet || ckv=$?
  test "$cfn" = "0" && test "$ckv" = "0"
}
if [[ -n "$PIP_READY" ]]; then run_gate "IaC (cfn-lint + checkov)" iac_gate; else note_skip "IaC (cfn-lint+checkov)" "python3/pip venv unavailable"; fi

# —— security.yml: Semgrep SAST (same rule-exclude as CI) ——
semgrep_gate() {
  [[ -n "$PIP_READY" ]] || { note_skip "Semgrep" "pip venv unavailable"; return 0; }
  pip install --quiet --require-hashes -r .github/scanner-requirements/semgrep/requirements.txt >/dev/null 2>&1 \
    || { echo "semgrep install failed"; return 1; }
  semgrep scan --config=auto --error \
    --exclude=node_modules --exclude=cdk.out \
    --exclude-rule=generic.secrets.security.detected-sonarqube-docs-api-key.detected-sonarqube-docs-api-key
}
if [[ -n "$PIP_READY" ]]; then run_gate "Semgrep SAST" semgrep_gate; else note_skip "Semgrep" "python3/pip venv unavailable"; fi

# —— security.yml: shellcheck (pinned engine) over tracked shell scripts ——
shellcheck_gate() {
  have shellcheck || { note_skip "shellcheck" "shellcheck not on PATH (mise install failed?)"; return 0; }
  mapfile -t scripts < <(git ls-files '*.sh' '*.bash')
  [[ ${#scripts[@]} -eq 0 ]] && return 0
  shellcheck "${scripts[@]}"
}
if have shellcheck; then run_gate "shellcheck (shell scripts)" shellcheck_gate; else note_skip "shellcheck" "shellcheck not on PATH"; fi

# —— security.yml: threat-model JSON structural check ——
threat_model_gate() {
  node -e '
    const tc = require("./threat-model.tc.json");
    const need = ["schema","applicationInfo","threats","mitigations","assumptions"];
    const missing = need.filter((k) => !(k in tc));
    if (missing.length) { console.error("Missing sections:", missing); process.exit(1); }
    if (!tc.threats.length) { console.error("No threats defined"); process.exit(1); }
    console.log("threat-model.tc.json OK:", tc.threats.length, "threats");
  '
}
run_gate "threat-model (structural)" threat_model_gate

# —— security.yml: VEX dialect drift-check (trivy.yaml / osv-scanner.toml) ——
run_gate "VEX dialect drift-check" node .github/scripts/vex-dialects.mjs check

# —— security.yml: MiniStack image-digest drift guard (ci.yml) ——
run_gate "MiniStack digest drift guard" .github/scripts/check-ministack-digest-drift.sh

# —— security.yml: actionlint (workflow correctness) ——
actionlint_gate() {
  have actionlint || { note_skip "actionlint" "actionlint not on PATH (pre-commit installs it, or brew/go install)"; return 0; }
  actionlint -color
}
if have actionlint; then run_gate "actionlint (workflows)" actionlint_gate; else note_skip "actionlint" "not on PATH — run via pre-commit"; fi

# ═════════════════════════ HEAVY-BUT-LOCAL GATES ════════════════════════════
# Docker / service-container gates. OPT-IN via RUN_DOCKER_GATES=1; otherwise
# auto-skip-with-notice so the scanner parity above still runs on a docker-less
# sandbox. This script does NOT provision the services (MiniStack/ClamAV/Sonar) —
# it prints the exact commands to run them, honoring the no-silent-skip rule.
hr "heavy-but-local (docker / service containers)"
if [[ "${RUN_DOCKER_GATES:-0}" != "1" ]]; then
  note_skip "Grype MiniStack image scan" "needs docker — set RUN_DOCKER_GATES=1 (VEX-gated, pinned digest)"
  note_skip "Trivy MiniStack image scan" "needs docker — set RUN_DOCKER_GATES=1 (VEX-gated, pinned digest)"
  note_skip "MiniStack E2E (deploy + integration)" "needs docker — see AGENTS.md § Commands (docker run ... + npm run bootstrap/deploy/test:integration)"
  note_skip "ClamAV virus scan" "needs the clamav/clamav service container"
  note_skip "SonarQube analysis" "needs the sonarqube:community service container"
elif ! have docker; then
  note_skip "docker image gates" "RUN_DOCKER_GATES=1 but docker is not available"
else
  # The pinned MiniStack digest — the single source of truth is ci.yml's
  # `docker run ... ministackorg/ministack:full@sha256:...` (the digest-drift guard
  # keeps every pin site identical). Extract it rather than hard-coding a 2nd copy.
  IMG="$(grep -oP 'ministackorg/ministack:full@sha256:[0-9a-f]{64}' .github/workflows/ci.yml | head -1)"

  # Grype MiniStack image scan — mirrors security.yml's `ministack-image` gate:
  # VEX-fed JSON (image CVE records only, `.vex/CVE-*`), then fail iff a high+
  # remains in matches[] (VEX-covered CVEs move to ignoredMatches[] and don't count).
  grype_image_gate() {
    shopt -s nullglob
    local vex=(.vex/CVE-*.openvex.json)
    local docs json="$WORK_DIR/grype-image.json"
    docs="$(printf '%s,' "${vex[@]}" | sed 's/,$//')"
    GRYPE_VEX_DOCUMENTS="$docs" grype "$IMG" --output json --file "$json" -q >/dev/null 2>&1 || return 1
    local uncovered
    uncovered="$(node -e '
      const d = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
      const hi = new Set(["High", "Critical"]);
      process.stdout.write(String((d.matches || []).filter((m) => hi.has(m?.vulnerability?.severity)).length));
    ' "$json")"
    echo "uncovered high+ in matches[]: $uncovered"
    test "$uncovered" = "0"
  }
  run_gate "Grype MiniStack image scan (VEX-gated)" grype_image_gate

  # Trivy MiniStack image scan — mirrors `trivy-image`: HIGH,CRITICAL floor with
  # VEX auto-loaded from the committed trivy.yaml (vulnerability.vex), exit 1 on any
  # uncovered high+. Trivy reads trivy.yaml from the CWD (the working channel #84).
  trivy_image_gate() {
    trivy image "$IMG" --scanners vuln --severity HIGH,CRITICAL --exit-code 1 --quiet
  }
  run_gate "Trivy MiniStack image scan (VEX-gated)" trivy_image_gate

  # E2E / ClamAV / SonarQube each need a running service (MiniStack + docker sock,
  # the clamav / sonarqube service containers). This script doesn't provision them;
  # note them so the gap is explicit rather than silently absent.
  note_skip "MiniStack E2E (deploy + integration)" "provision MiniStack per AGENTS.md § Commands, then npm run bootstrap/deploy/test:integration"
  note_skip "ClamAV / SonarQube" "provision the clamav / sonarqube service containers, then run per security.yml"
fi

# ═════════════════════════════ CI-ONLY (no local twin) ══════════════════════
hr "CI-only (no faithful local twin — documented, not run here)"
cat <<'EOF'
  · CodeQL (JS/TS)          — heavy analyzer bundle; Security-tab gate. CI-only.
  · dependency-review (PR)  — needs the base↔head PR dep-diff; no local twin.
  · octocov coverage comment / SBOM (Syft) / SARIF uploads — REPORTING-only side
    effects, not gates (by design NOT localized; see #185 non-goals).
  · gitleaks / zizmor       — runnable locally (pre-commit covers gitleaks); the
    unit-tier + pre-commit already gate the fast subset.
EOF

# ═════════════════════════════════ SUMMARY ══════════════════════════════════
hr "SUMMARY"
printf '  \033[32mPASSED\033[0m : %d\n' "${#PASSED[@]}"
printf '  \033[31mFAILED\033[0m : %d\n' "${#FAILED[@]}"
printf '  \033[33mSKIPPED\033[0m: %d\n' "${#SKIPPED[@]}"
if [[ ${#SKIPPED[@]} -gt 0 ]]; then
  echo "  Skipped gates (and why):"
  printf '    · %s\n' "${SKIPPED[@]}"
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "  Failed gates:"
  printf '    · %s\n' "${FAILED[@]}"
  echo ""
  echo "✗ verify:all FAILED — fix the gates above before pushing."
  exit 1
fi
echo ""
echo "✓ verify:all: all RUN gates passed. Note the honest residual: the vuln DB"
echo "  floats (#183), so a freshly-disclosed CVE can still red CI — parity is"
echo "  near-zero round-trips, not exactly zero."
exit 0
