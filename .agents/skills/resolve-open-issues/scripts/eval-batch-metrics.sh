#!/usr/bin/env bash
# eval-batch-metrics.sh — reconstruct the resolve-open-issues skill's §5 metrics
# for a batch of merged PRs from PUBLIC GitHub artifacts only.
#
# Why this exists: the skill claims "public GitHub artifacts are the source of truth"
# (SKILL.md §5). This harness proves it — every metric the skill tracks live during a
# run (lead/ci/review time, auto-close correctness) is recomputable AFTER THE FACT from
# `gh` JSON, with no instrumentation hooks. That makes it a fair, repeatable scorecard
# for measuring a skill change: run it on the PRs produced before a skill edit and on
# the PRs produced after, and compare.
#
# Dependencies: bash, gh (authenticated), jq, and the pinned node. NO new third-party
# tool/dep/action — adding one would trip the skill's own governance gate
# (prompts/subagent-issue.md § Adopting a NEW tool).
#
# Usage:
#   eval-batch-metrics.sh [--repo owner/name] [--branch-prefix fix/issue-] \
#       [--limit N] [--label LABEL] [--json] [--since YYYY-MM-DD]
#
#   # All merged worker PRs in the current repo, human-readable table:
#   ./eval-batch-metrics.sh
#
#   # Machine-readable, for diffing two batches:
#   ./eval-batch-metrics.sh --json > before.json
#   ./eval-batch-metrics.sh --json > after.json
#   ./eval-compare.sh before.json after.json
#
# Output columns (per PR) + a batch summary:
#   pr, issues, build/lead/ci/review minutes, ci_runs, ci_conclusion, autoclose_ok
#
set -euo pipefail

# --- args ---------------------------------------------------------------------
REPO=""
BRANCH_PREFIX="fix/issue-"
LIMIT=100
LABEL=""
EMIT_JSON=0
SINCE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --repo) REPO="$2"; shift 2 ;;
    --branch-prefix) BRANCH_PREFIX="$2"; shift 2 ;;
    --limit) LIMIT="$2"; shift 2 ;;
    --label) LABEL="$2"; shift 2 ;;
    --since) SINCE="$2"; shift 2 ;;
    --json) EMIT_JSON=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

for bin in gh jq; do
  command -v "$bin" >/dev/null 2>&1 || { echo "error: '$bin' not found on PATH" >&2; exit 3; }
done

if [ -z "$REPO" ]; then
  REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
fi
OWNER="${REPO%%/*}"; NAME="${REPO##*/}"

# --- helpers ------------------------------------------------------------------
# epoch from an ISO-8601 timestamp; portable across GNU/BSD date. Empty -> empty.
iso2epoch() {
  local ts="$1"
  [ -z "$ts" ] || [ "$ts" = "null" ] && { echo ""; return; }
  date -u -d "$ts" +%s 2>/dev/null || date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$ts" +%s 2>/dev/null || echo ""
}
# minutes between two epochs, or "" if either is missing.
mins() {
  local a="$1" b="$2"
  { [ -z "$a" ] || [ -z "$b" ]; } && { echo ""; return; }
  echo $(( (b - a) / 60 ))
}

# --- collect the batch --------------------------------------------------------
# Merged PRs whose head branch matches the worker convention (or all, if prefix="").
gh_args=(pr list --repo "$REPO" --state merged --limit "$LIMIT" --json \
         "number,headRefName,createdAt,mergedAt,closingIssuesReferences,additions,deletions")
[ -n "$LABEL" ] && gh_args+=(--label "$LABEL")
PRS_JSON=$(gh "${gh_args[@]}")

# filter by branch prefix and optional --since (mergedAt) in jq
SINCE_EPOCH=""
[ -n "$SINCE" ] && SINCE_EPOCH=$(iso2epoch "${SINCE}T00:00:00Z")
FILTERED=$(echo "$PRS_JSON" | jq --arg p "$BRANCH_PREFIX" '
  [ .[] | select(.headRefName | startswith($p)) ]')

COUNT=$(echo "$FILTERED" | jq 'length')
if [ "$COUNT" -eq 0 ]; then
  echo "No merged PRs with branch prefix '$BRANCH_PREFIX' in $REPO." >&2
  exit 0
fi

# --- per-PR metric reconstruction --------------------------------------------
# Emits one compact JSON object per PR to a temp accumulator, then summarizes.
ROWS="[]"
for pr in $(echo "$FILTERED" | jq -r '.[].number'); do
  base=$(echo "$FILTERED" | jq -c --argjson n "$pr" '.[] | select(.number==$n)')
  created=$(echo "$base" | jq -r '.createdAt')
  merged=$(echo "$base" | jq -r '.mergedAt')
  issues=$(echo "$base" | jq -c '[.closingIssuesReferences[]?.number]')

  if [ -n "$SINCE_EPOCH" ]; then
    me=$(iso2epoch "$merged"); [ -n "$me" ] && [ "$me" -lt "$SINCE_EPOCH" ] && continue
  fi

  # draft->ready transition (review_latency boundary): last ready_for_review event.
  ready=$(gh api "repos/$OWNER/$NAME/issues/$pr/timeline" --paginate \
            --jq '[.[]|select(.event=="ready_for_review")|.created_at]|last' 2>/dev/null || echo "")
  [ "$ready" = "null" ] && ready=""

  # CI window: check-runs on the PR head SHA. started=min, completed=max.
  sha=$(gh pr view "$pr" --repo "$REPO" --json commits --jq '.commits[-1].oid' 2>/dev/null || echo "")
  ci_started=""; ci_done=""; ci_runs=0; ci_concl="unknown"
  if [ -n "$sha" ]; then
    cr=$(gh api "repos/$OWNER/$NAME/commits/$sha/check-runs" 2>/dev/null || echo '{"check_runs":[]}')
    ci_started=$(echo "$cr" | jq -r '[.check_runs[].started_at]|map(select(.!=null))|sort|first // ""')
    ci_done=$(echo "$cr" | jq -r '[.check_runs[]|select(.conclusion!=null)|.completed_at]|sort|last // ""')
    ci_runs=$(echo "$cr" | jq '.check_runs|length')
    # all green if every conclusion is success or skipped/neutral.
    ci_concl=$(echo "$cr" | jq -r '
      ([.check_runs[].conclusion]|map(select(.!=null))) as $c
      | if ($c|length)==0 then "none"
        elif ($c|all(. as $x | ["success","skipped","neutral"]|index($x))) then "green"
        else "had-red" end')
  fi

  # autoclose correctness: did the PR link >=1 closing issue? (the skill's verify step)
  autoclose=$(echo "$issues" | jq 'length>0')

  ce=$(iso2epoch "$created"); re=$(iso2epoch "$ready"); mge=$(iso2epoch "$merged")
  cse=$(iso2epoch "$ci_started"); cde=$(iso2epoch "$ci_done")

  row=$(jq -n \
    --argjson pr "$pr" --argjson issues "$issues" \
    --arg created "$created" --arg ready "$ready" --arg merged "$merged" \
    --arg lead "$(mins "$ce" "$mge")" \
    --arg ci "$(mins "$cse" "$cde")" \
    --arg review "$(mins "$re" "$mge")" \
    --argjson ci_runs "$ci_runs" --arg ci_concl "$ci_concl" \
    --argjson autoclose "$autoclose" \
    '{pr:$pr, issues:$issues, lead_min:($lead|tonumber? // null),
      ci_min:($ci|tonumber? // null), review_min:($review|tonumber? // null),
      ci_runs:$ci_runs, ci_conclusion:$ci_concl, autoclose_ok:$autoclose}')
  ROWS=$(echo "$ROWS" | jq --argjson r "$row" '. + [$r]')
done

# --- batch summary ------------------------------------------------------------
SUMMARY=$(echo "$ROWS" | jq '{
  repo_pr_count: length,
  lead_min:   { median: ([.[].lead_min]   | map(select(.!=null)) | sort | (if length==0 then null else .[(length/2)|floor] end)),
                max: ([.[].lead_min]|map(select(.!=null))|max) },
  ci_min:     { median: ([.[].ci_min]     | map(select(.!=null)) | sort | (if length==0 then null else .[(length/2)|floor] end)) },
  review_min: { median: ([.[].review_min] | map(select(.!=null)) | sort | (if length==0 then null else .[(length/2)|floor] end)) },
  first_try_green_pct: (([.[]|select(.ci_conclusion=="green")]|length) * 100 / (length)),
  autoclose_ok_pct:    (([.[]|select(.autoclose_ok)]|length) * 100 / (length))
}')

if [ "$EMIT_JSON" -eq 1 ]; then
  jq -n --argjson rows "$ROWS" --argjson summary "$SUMMARY" \
    --arg repo "$REPO" --arg prefix "$BRANCH_PREFIX" \
    '{repo:$repo, branch_prefix:$prefix, summary:$summary, prs:$rows}'
  exit 0
fi

# human-readable table
printf '\n# resolve-open-issues batch scorecard — %s (branch prefix "%s")\n\n' "$REPO" "$BRANCH_PREFIX"
printf '%-6s %-12s %8s %8s %8s %6s %-9s %-9s\n' PR issues lead_m ci_m review_m runs ci autoclose
printf '%-6s %-12s %8s %8s %8s %6s %-9s %-9s\n' ----- ------ ------ ---- -------- ---- -- ---------
echo "$ROWS" | jq -r '.[] | [
  ("#"+(.pr|tostring)),
  (.issues|map("#"+(.|tostring))|join(",")|if .=="" then "-" else . end),
  (.lead_min // "-"), (.ci_min // "-"), (.review_min // "-"),
  .ci_runs, .ci_conclusion, (if .autoclose_ok then "ok" else "MISSING" end)
] | @tsv' | while IFS=$'\t' read -r a b c d e f g h; do
  printf '%-6s %-12s %8s %8s %8s %6s %-9s %-9s\n' "$a" "$b" "$c" "$d" "$e" "$f" "$g" "$h"
done

echo
echo "## Summary"
echo "$SUMMARY" | jq -r '
  "PRs scored:          \(.repo_pr_count)",
  "lead time (median):  \(.lead_min.median // "-") min   (max \(.lead_min.max // "-"))",
  "CI time (median):    \(.ci_min.median // "-") min",
  "review wait (median):\(.review_min.median // "-") min",
  "first-try green:     \(.first_try_green_pct|floor)%",
  "auto-close correct:  \(.autoclose_ok_pct|floor)%"'
