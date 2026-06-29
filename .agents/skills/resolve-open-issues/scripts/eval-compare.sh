#!/usr/bin/env bash
# eval-compare.sh — diff two batch scorecards produced by `eval-batch-metrics.sh --json`.
#
# Why: a skill change is only "an improvement" relative to a baseline. Capture the
# before-batch and after-batch scorecards, then this prints the delta on each summary
# metric so a skill edit's effect is measured, not asserted.
#
# Usage:
#   eval-batch-metrics.sh --json > before.json   # PRs from the pre-change batch
#   eval-batch-metrics.sh --json > after.json    # PRs from the post-change batch
#   eval-compare.sh before.json after.json
#
# Deps: bash, jq. No new third-party tooling (skill governance gate).
set -euo pipefail

[ $# -eq 2 ] || { echo "usage: eval-compare.sh before.json after.json" >&2; exit 2; }
command -v jq >/dev/null 2>&1 || { echo "error: 'jq' not found" >&2; exit 3; }
BEFORE="$1"; AFTER="$2"

# Lower-is-better for time metrics; higher-is-better for the percentage metrics.
jq -n --slurpfile b "$BEFORE" --slurpfile a "$AFTER" '
  ($b[0].summary) as $bs | ($a[0].summary) as $as |
  def delta(x): (x.a - x.b);
  def arrow(x; lowerBetter):
    if x.a == null or x.b == null then "·"
    elif (x.a == x.b) then "="
    elif (lowerBetter and x.a < x.b) or ((lowerBetter|not) and x.a > x.b) then "improved"
    else "regressed" end;
  {
    "PRs scored":          {b:$bs.repo_pr_count,            a:$as.repo_pr_count},
    "lead median (min)":   {b:$bs.lead_min.median,          a:$as.lead_min.median},
    "CI median (min)":     {b:$bs.ci_min.median,            a:$as.ci_min.median},
    "review median (min)": {b:$bs.review_min.median,        a:$as.review_min.median},
    "first-try green %":   {b:($bs.first_try_green_pct|floor), a:($as.first_try_green_pct|floor)},
    "auto-close ok %":     {b:($bs.autoclose_ok_pct|floor),    a:($as.autoclose_ok_pct|floor)}
  } as $rows |
  ( $rows | to_entries[] |
    .key as $k | .value as $v |
    ($k | . + (" " * (22 - length))) as $label |
    ($v.b // "-" | tostring) as $bv | ($v.a // "-" | tostring) as $av |
    (if ($k|test("green|ok")) then arrow($v; false) else arrow($v; true) end) as $dir |
    "\($label)  before=\($bv)\t after=\($av)\t [\($dir)]"
  )
' -r
echo
echo "Note: time medians are lower-is-better; the two % metrics are higher-is-better."
echo "'·' = not comparable (a side had no data). Small N: read the per-PR rows, not just medians."
