#!/usr/bin/env bash
# Guard against MiniStack image digest drift (#212).
#
# The pinned MiniStack image digest is duplicated across several pin sites
# (workflows, AGENTS.md, README.md, and the compat registry). A partial bump
# — updating some sites but not all — would silently drift. This check greps
# every real full-digest pin across the tracked tree, adds the registry's
# `digest` field, collects the unique set, and FAILS if more than one distinct
# digest exists. It passes when every site agrees.
#
# Dependency-free: git + grep + sed + jq (jq is already required by
# scripts/check-mcp-parity.sh, so it adds no new tool). Runs on ubuntu-latest.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

# Match ONLY a real, full 64-hex-char pin — never the truncated prose
# (`636c4ef5...`) in comments or the `sha256:...` placeholder in the issue
# template. `git grep` scans tracked files only, so node_modules is excluded
# for free.
PIN_RE='ministackorg/ministack:full@sha256:[0-9a-f]{64}'
DIGEST_RE='sha256:[0-9a-f]{64}'

REGISTRY="services/_registry/ministack-pin.json"

# Collect "file:line:<digest>" hits so we can report offenders on failure.
hits="$(mktemp)"
trap 'rm -f "$hits"' EXIT

# git grep exits 1 on no match; guard with `|| true` so an empty result doesn't
# abort under `set -e` before we can report it below. Reduce each match to
# `file:line:<digest>` (git grep's `file:line:` prefix + the 64-hex digest).
git grep -nE "$PIN_RE" -- . \
  | sed -E "s/^([^:]+:[0-9]+:).*($DIGEST_RE).*/\1\2/" \
  >>"$hits" || true

# Add the registry's `digest` field (JSON) as a synthetic hit line.
if [[ -f "$REGISTRY" ]]; then
  if ! command -v jq >/dev/null 2>&1; then
    echo "check-ministack-digest-drift: jq is required to read ${REGISTRY}" >&2
    exit 1
  fi
  reg_digest="$(jq -r '.digest' "$REGISTRY")"
  echo "${REGISTRY}:digest:${reg_digest}" >>"$hits"
fi

if [[ ! -s "$hits" ]]; then
  echo "check-ministack-digest-drift: found NO MiniStack digest pins — expected at least one." >&2
  exit 1
fi

# The digest is the trailing sha256:<hex> of every hit line.
unique_digests="$(sed -E "s/.*($DIGEST_RE).*/\1/" "$hits" | sort -u)"
count="$(printf '%s\n' "$unique_digests" | grep -c .)"

if [[ "$count" -ne 1 ]]; then
  echo "check-ministack-digest-drift: MiniStack image digest DRIFT — ${count} distinct digests across pin sites:" >&2
  echo >&2
  while IFS= read -r d; do
    [[ -z "$d" ]] && continue
    echo "  ${d}" >&2
    grep -F "$d" "$hits" | sed 's/^/    /' >&2
  done <<<"$unique_digests"
  echo >&2
  echo "All pin sites must carry the SAME digest. Bump every site together (see docs/PINNING.md)." >&2
  exit 1
fi

echo "check-ministack-digest-drift: OK — all MiniStack digest pins agree on ${unique_digests}"
sed -E "s/:$DIGEST_RE$//" "$hits" | sed 's/^/    /'
