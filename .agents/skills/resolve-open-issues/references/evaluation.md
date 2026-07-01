# Evaluating skill changes — baseline + instrumentation

Load this when measuring whether a change to this skill actually improved batch behavior (not
during a normal run). It answers: _"how do we know an edit to `resolve-open-issues` made the
pipeline better, rather than just different?"_

## Principle: the public artifacts ARE the instrumentation

The skill already asserts that the **public GitHub artifacts are the source of truth** (SKILL.md
§5) — issue claims/sign-outs, open PRs, CI status, `closingIssuesReferences`. The corollary, used
here, is that **every metric the skill tracks live during a run is recomputable after the fact** from
those same artifacts. So evaluation needs **no new instrumentation hooks** inside the orchestrator —
it reads `gh` JSON for a set of already-merged PRs and reconstructs the §5 metrics. That keeps the
eval honest (it measures shipped reality, not the orchestrator's self-report) and dependency-free.

## What gets measured (maps 1:1 to SKILL.md §5)

| Metric               | Reconstructed from                                         | Reads as                                                 |
| -------------------- | ---------------------------------------------------------- | -------------------------------------------------------- |
| `lead_time`          | `mergedAt − createdAt`                                     | end-to-end PR latency                                    |
| `ci_time`            | check-runs `completed − started` on the head SHA           | CI duration (the usual long pole)                        |
| `review_latency`     | `mergedAt −` the `ready_for_review` timeline event         | merge wait after promotion                               |
| first-try-green %    | check-run conclusions all in {success, skipped, neutral}   | how often a worker's draft was green without a fix cycle |
| auto-close correct % | `closingIssuesReferences` non-empty for a `fix/issue-*` PR | did the worker wire `Closes #N` (the §7 verify step)     |

`build_time` (`draft_at − dispatched_at`) is the one metric **not** publicly reconstructable — the
dispatch instant lives only in the orchestrator's ledger, not on GitHub. Capture it from the ledger
if a before/after comparison needs worker-speed; the harness omits it and says so rather than
guessing.

## The harness

- **`scripts/eval-batch-metrics.sh`** — scores a batch of merged worker PRs (default: all
  `fix/issue-*` PRs in the current repo). Human table by default; `--json` for a machine-readable
  scorecard. ~3 `gh` API calls per PR (timeline, head commit, check-runs) — mind the rate-limit
  budget (`references/ci-and-rate-limits.md`) on large batches; use `--limit`/`--since` to bound it.
- **`scripts/eval-compare.sh before.json after.json`** — diffs two `--json` scorecards and prints
  the per-metric delta with an improved/regressed marker (time medians are lower-is-better; the two
  percentages are higher-is-better).

Both are bash + `gh` + `jq` + the pinned `node` — **zero new dependencies**, on purpose: adding an
eval-only tool would trip the skill's own governance gate (`prompts/subagent-issue.md` § Adopting a
NEW tool), so the harness eats its own dog food.

## How to run an evaluation (the before/after protocol)

1. **Baseline.** Before landing a skill change, score the most recent batch the _old_ skill
   produced: `eval-batch-metrics.sh --json > before.json`. (For e2e-ministack the current committed
   baseline lives in [`baselines/`](#committed-baselines) below.)
2. **Change the skill**, then run a fresh batch (ideally a comparable backlog — similar size and
   cluster mix; note any difference, **because** a harder backlog confounds the comparison).
3. **After.** Score the new batch: `eval-batch-metrics.sh --json > after.json`.
4. **Compare.** `eval-compare.sh before.json after.json`. Read the per-PR rows too, not just the
   medians — small N makes a single slow PR move a median.
5. **Attribute carefully.** CI duration and review wait are partly outside the skill's control (CI
   tier speed, human availability). The metrics most attributable to a _skill_ change are
   **first-try-green %** (better worker prompts → fewer red→fix cycles) and **auto-close correct %**
   (the §7 verify/close discipline). Lead/review time are context, not verdict.

## Committed baselines

Baselines are committed under `baselines/` **because** a skill edit is only falsifiable against a
snapshot taken _before_ the edit — regenerating "before" after the change would score PRs the new
skill produced (issue #107).

| File                                                                      | Slice                                                                                                                                                                     |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`baselines/2026-07-01-before.json`](../baselines/2026-07-01-before.json) | All 42 merged `fix/issue-*` PRs in e2e-ministack as of 2026-07-01 (through PR #118). Snapshots the **pre-#110** skill — the "before" for the portability refactor (#110). |

## Caveats the harness prints (don't over-read the number)

- **auto-close "MISSING" is a flag, not a verdict.** A `fix/issue-*` PR with no closing link is
  _either_ a real strand (the worker forgot `Closes #N`, or backticked it — `` `Closes #N` `` does
  NOT auto-close) _or_ an intentional DONE-NO-CLOSE / infra PR that legitimately closes nothing. The
  harness can't tell them apart without the worker's reported intent, so it flags for human review
  rather than asserting a bug. (Real example in this repo: PRs whose title references `#83` but whose
  body linked no closing keyword.)
- **first-try-green is computed on the merged head SHA**, so a PR that went red then got fixed before
  the final push can still read green here — it measures the _shipped_ commit's CI, a lower bound on
  rework. Pair it with the orchestrator's ledger `rebase_count`/retry log for the full picture.
- **Medians over small batches are noisy.** Report N alongside every median; prefer the full row
  dump when N < ~8.
