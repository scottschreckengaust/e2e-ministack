#!/usr/bin/env bash
# Guard against Node.js version-pin drift (#329).
#
# The Node pin has two GENUINELY independent sources, because neither side can
# read the other:
#
#   1. `mise.toml`                        -> the LOCAL toolchain (`mise install`)
#   2. `.github/actions/setup/action.yml` -> CI, via the `node-version` input default
#
# They must agree, or the #185 local<->CI parity contract silently breaks (an
# agent validates on one Node and CI runs another). Before this guard, the
# agreement was merely ASSERTED in a comment — and the comment was false: a
# third literal had been duplicated into `security.yml` with a note claiming it
# was "single-sourced" from mise.toml. A claim of single-sourcing that nothing
# enforces is exactly the drift class the repo-revisit audit exists to catch, so
# this check makes it fail-closed instead.
#
# It therefore asserts BOTH halves:
#   (a) the two sources carry the same exact version, and
#   (b) NO workflow or other composite action reintroduces a raw `node-version:`
#       literal — every job must go through `./.github/actions/setup`, which is
#       also the single `actions/setup-node` pin site (#327).
#
# This is a DRIFT gate, not a currency gate: it proves the pin sites agree, not
# that the pin is the newest Node. Currency is #99's job.
#
# Dependency-free: git + grep + sed (all present on ubuntu-latest), so it adds no
# new tool and no new gate dependency.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

MISE="mise.toml"
ACTION=".github/actions/setup/action.yml"

fail() {
  echo "check-node-pin-drift: $*" >&2
  exit 1
}

[[ -f "$MISE" ]] || fail "missing ${MISE}"
[[ -f "$ACTION" ]] || fail "missing ${ACTION}"

# ── Source 1: mise.toml `node = "X.Y.Z"` ───────────────────────────────────
# Anchored at column 0 so a commented-out or nested key can't be picked up.
mise_version="$(
  sed -nE 's/^node[[:space:]]*=[[:space:]]*"([0-9]+\.[0-9]+\.[0-9]+)".*/\1/p' "$MISE" | head -1
)"
[[ -n "$mise_version" ]] ||
  fail "could not read an exact 'node = \"X.Y.Z\"' pin from ${MISE}"

# ── Source 2: the composite's `node-version` input default ─────────────────
# Take the FIRST `default:` at or after the `node-version:` input key, so the
# sibling `npm-ci` input's default can never be mistaken for it.
# The trailing `|| true` keeps a missing/renamed key on the EXPLICIT error path
# below: without it, `set -e` + `pipefail` would abort the assignment first and
# exit 1 with no diagnostic at all. Still fail-closed either way — just legible.
composite_version="$(
  grep -A6 -E "^[[:space:]]+node-version:[[:space:]]*$" "$ACTION" |
    grep -m1 -E "^[[:space:]]+default:" |
    sed -E "s/.*default:[[:space:]]*['\"]?([0-9]+\.[0-9]+\.[0-9]+)['\"]?.*/\1/" || true
)"
[[ -n "$composite_version" ]] ||
  fail "could not read the 'node-version' input default from ${ACTION}"

if [[ "$mise_version" != "$composite_version" ]]; then
  fail "$(
    printf 'Node pin DRIFT — the two sources disagree:\n'
    printf '    %-40s %s\n' "${MISE} (node =)" "$mise_version"
    printf '    %-40s %s\n' "${ACTION} (node-version default)" "$composite_version"
    printf '\n  Bump BOTH in the same commit (see docs/PINNING.md).'
  )"
fi

# ── (b) No workflow / other composite may hardcode a Node version ──────────
# Pattern 1 matches only a line whose first non-space token is `node-version:`
# followed by a digit, so `#`-comments, `id: node-version` and the composite's own
# `node-version: ${{ inputs.node-version }}` passthrough are all excluded.
# Pattern 2 closes the back door: `node-version-file:` (e.g. a `.nvmrc`) is an
# ALTERNATIVE Node source that pattern 1 cannot see, so any use of it would be a
# third pin site. Unused in this repo today — kept rejected so it stays that way.
# `git grep` scans tracked files only, so node_modules is excluded for free.
strays="$(
  git grep -nE \
    -e "^[[:space:]]*node-version:[[:space:]]*['\"]?[0-9]" \
    -e "^[[:space:]]*node-version-file:[[:space:]]*[^[:space:]]" \
    -- .github/workflows .github/actions || true
)"
if [[ -n "$strays" ]]; then
  fail "$(
    printf 'a raw node-version literal was reintroduced:\n'
    printf '%s\n' "$strays" | sed 's/^/    /'
    printf '\n  Use "uses: ./.github/actions/setup" instead — it carries the single\n'
    printf '  CI Node pin and the single actions/setup-node SHA (#327/#329). If a job\n'
    printf '  genuinely needs a different Node, add an input to the composite rather\n'
    printf '  than a second literal.'
  )"
fi

echo "check-node-pin-drift: OK — Node pinned to ${mise_version} in both sources, no stray literals"
printf '    %-40s %s\n' "${MISE} (node =)" "$mise_version"
printf '    %-40s %s\n' "${ACTION} (node-version default)" "$composite_version"
