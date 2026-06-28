# Concurrency dial, the merge-train & the merge-closer

Load this when tuning pipeline width or merging the front PR. The core caps live in `SKILL.md`
§2; this file is how they move and how the train turns.

## The merge-train model

**Serialize the _merge_ stage, parallelize the _build_ stage wide.**

- **Widen the DRAFT funnel** — the real throughput dial is the number of outstanding drafts,
  `max_draft = max_in_flight − ready_count`. Workers build many issues' PRs in parallel as drafts.
- **Keep a small "Ready" front** — start at exactly ONE (`max_ready = 1`): the front of the train,
  rebased onto latest `main` and all-green.
- **Train cycle:** front PR merges → `main` advances → pick the next draft → **rebase onto the new
  `main` → wait for all-green → flip it Ready → it merges** → repeat. Each lands against the _final_
  tree → near-zero rebase thrash, while builds stay fully parallel behind it.

## The concurrency dial

The dial is a per-loop decision: read the metrics (below), move a notch, proceed. The columns are
the _shape_ of how the caps move, not fixed profiles.

| knob            | under stress        | steady (default)          | wide-open                   |
| --------------- | ------------------- | ------------------------- | --------------------------- |
| `max_ready`     | 1                   | 1                         | 2–3 (smooth + low-conflict) |
| `max_in_flight` | floor 1–2           | injected `N` (default 3)  | up to ceiling 1000          |
| `max_draft`     | `in_flight − ready` | `in_flight − ready`       | `in_flight − ready`         |
| merge gating    | one-at-a-time       | train: rebase→green→merge | parallel + rebase           |
| folding         | aggressive          | coupled-trivial only      | minimal                     |

- **Ratchet DOWN when** rebases exceed ~2/PR, CI failures cluster, a rate-limit throttle is active,
  or the human wants careful sequential review. Drop `max_in_flight` first; only drop `max_ready`
  to 1 if a wider front is causing rebase thrash.
- **Ratchet UP when** the box is idle, CI passes first-try consistently, remaining issues touch
  independent files, and review/merge latency is the long pole — widen the draft funnel so the
  front is never starved, and (only if conflicts stay rare) grow `max_ready`.

## `max_in_flight` / `max_ready` are launch-seeded + adaptive

The open-PR width is **set at launch by the human**, not discovered, **because** the repo's
"max open PRs per user" setting has **no API** (see `gotchas.md`) — so the orchestrator must NOT
try to read or scrape it.

- **If `--max-in-flight N` was injected at launch, use it as the hard ceiling. If it is absent, ASK
  before dispatching**, pointing at where to read it:

  > How many open PRs may I keep in flight at once? Your repo's per-user cap is on
  > `https://github.com/<owner>/<repo>/settings/interaction_limits` ("maximum open pull requests
  > per user"). I can't read it via API — it's UI-only. Default **3** to start conservative;
  > ceiling is 1000.

- **Range `1..1000`** (1000 mirrors the GitHub UI's own max).
- **Adaptive ratchet (seed both from the answer):**
  - `max_in_flight` — start at `N`. While CI passes first-try AND `gh api rate_limit` core-remaining
    stays healthy (>1000), ratchet **UP by 1 each clean loop** (never past the ceiling). On ANY
    rate-limit signal (own-API or an Actions-side throttle — see `ci-and-rate-limits.md`), ratchet
    **DOWN by 1** (floor 1) and widen the CI-poll interval.
  - `max_ready` — start at **1**. Grow it (cap ~3) only after several consecutive clean merges with
    rebases averaging <1/PR and remaining work spread across **disjoint** clusters (a wider front is
    safe only when fronts don't conflict). Shrink to 1 the moment rebase thrash reappears.
  - **Log every change** in the ledger (`knob: old→new` + trigger) **because** that makes a silent
    runaway impossible to hide.

## Pilot mode (optional on-ramp)

**Steady-state** is the normal mode: the §4 loop with the ratchet live. **Pilot mode** differs only
by **holding the ratchet flat** until the first worker has gone fully BACKLOG→MERGED once — it
exists **because** the first end-to-end pass is what surfaces repo-specific surprises (a flaky gate,
a slow CI tier, a missing permission), and you'd rather learn that at width 1–3 than mid-widening.
Once one PR merges clean, release the ratchet. Skip pilot mode on a repo you've already run this on.
Set `N=1` for a strict single-issue dry run.

**Thin backlog is fine, not a failure.** If fewer issues exist than `max_in_flight`, the train just
runs narrower — `max_in_flight` is a ceiling, not a quota. A 2-issue backlog with `N=3` means two
workers and an early, tidy finish via the normal STOP condition.

## The merge-closer (the always-on merger/approver)

The engine that keeps the train turning even when no worker is reporting **is the orchestrator
itself** running its loop on the `ScheduleWakeup` cadence — NOT a separate subagent, **because** only
the main loop can self-schedule (a background "merger subagent" would run once and die). Its
responsibilities every wakeup:

1. **Know what the repo requires** — check `gh api repos/{o}/{r}/branches/main/protection` once and
   cache it.
   - **No branch protection** (`Branch not protected`): no approval needed; the orchestrator merges
     the green front PR directly.
   - **Reviews required:** ⚠️ a PR **cannot be approved by its own author** — every PR here is
     authored by your `gh` login, so `gh pr review --approve` returns `422`. Do not pretend to;
     surface it and present options: (a) a human/second account approves, (b) relax the review
     requirement, or (c) admin merge if policy allows (`gh pr merge --admin`, log that it was used).
2. **Merge the green front PR.** Prefer **native auto-merge** (`gh pr merge <pr> --auto --squash`)
   **because** it survives your session and merges server-side the instant checks pass (requires
   branch protection + required checks to be meaningful). Absent protection, merge directly on green
   (`gh pr merge <pr> --squash`). Never merge a red/pending PR.
3. **Close / reconcile the issue** — verify auto-close fired (see `escalation-and-signout.md` §
   auto-close); confirm the worker shows as GH assignee, and `gh issue edit <N> --add-assignee @me`
   as a backstop if a dispatch skipped self-assign.
4. **Advance + refill** — run the rebase+refill cascade (SKILL.md §6), then `ScheduleWakeup` again.

This is "constantly running" in the only way the harness allows: a durable, crash-recoverable loop
(the ledger lets a fresh session resume it), not a daemon.

## Derived metrics (drive the dial)

From the six per-issue epoch stamps (SKILL.md §5):

- `build_time = draft_at − dispatched_at` (worker speed)
- `ci_time = ci_green_at − draft_at` (CI duration — usually the long pole; also sets the poll
  interval, see `ci-and-rate-limits.md`)
- `review_latency = merged_at − ready_at` (human merge wait)
- `lead_time = merged_at − dispatched_at` (end-to-end)
- Batch-level: `throughput = merged / ((now − BATCH_START)/3600)` (PRs/hr), live `WIP`,
  `rebase_count`, `blocked_count`.

Use them: high `review_latency` ⇒ don't add build parallelism (the front, not the build, is the
bottleneck); high `rebase_count` ⇒ ratchet down.
