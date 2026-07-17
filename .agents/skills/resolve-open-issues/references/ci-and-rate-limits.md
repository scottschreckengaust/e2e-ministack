# CI green-gate, subagent resume & rate limits

Load this when a check is pending/red, when a subagent needs waking, or when you hit a rate limit.

## The green-gate

Each loop, for every DRAFT/READY PR, read `gh pr checks <pr>` (or `statusCheckRollup`) and classify:

- **all-green** — 0 failed, 0 pending; `skipping` is fine (e.g. fuzz is skipped on PRs). Stamp
  `ci_green_at`; promote if a ready slot is free.
- **pending** — do nothing yet; ensure a CI_POLL wakeup is set and re-check next loop.
- **red** (`FAILURE`/`CANCELLED`/`TIMED_OUT`) — **classify before acting** (rate-limit section
  below): a transient failure is re-run, NOT fixed; a real failure wakes the subagent. Don't
  promote either way.

Read status with a **compact single-shot** call — `gh pr view <pr> --json statusCheckRollup` (or
`gh pr checks <pr> --json`) — never `gh pr checks --watch`, **because** a JSON snapshot costs a few
lines per poll while a watch stream re-dumps the full check table every interval into the
orchestrator's context (see SKILL.md § Lean orchestrator / context hygiene).

A worker **does not poll its own CI** at all, **because** it would busy-wait ~15–30 min burning its
context for no work, it has already signed out, and its local gates already caught instant
lint/unit breaks before the push — so a self-check would only duplicate the orchestrator's first
poll one cycle later. The orchestrator's single timer covers _all_ open PRs at once.

## Waking the subagent on a real red

Background subagents **cannot self-schedule** a wakeup, so the split is: **orchestrator schedules
the re-check; the subagent performs the fix.**

**Never tail the CI log inline in the orchestrator to diagnose the red.** Log-fetching /
`--log-failed` / log tails are large-output ops — delegate them to a short-lived subagent that
reads the log and returns ONLY a one-line classification (`{ state: real|transient, one-line
reason, failing test:line }`), **because** dumping a 60-line log into the main loop fills context
and risks summarizing this skill's instructions away (SKILL.md § Lean orchestrator / context
hygiene). Then act on that verdict:

- **Warm resume** (its `agentId` is still live & recent per the ledger): `SendMessage` the failing
  check + log tail and "fix on your existing branch/worktree, push, then report" — keeps its
  context.
- **Cold resume** (after a crash, agentId lost): dispatch a **fresh** worker with the per-issue
  prompt + "branch/worktree/PR `<exact branch>` already exist — resume there, do not recreate" + the
  failing-check detail.

**Get the exact branch from the public artifacts, never a guess:** the PR's head branch
(`gh pr view <PR> --json headRefName`), or the worker's claim comment, or `gh pr list` /
`git ls-remote --heads origin 'fix/issue-*'`. The branch is named for the worker's primary issue but
its slug is **free-text**, so never reconstruct it from a `fix/issue-N` pattern — read it. This is
why the claim comment + PR are the source of truth: cold resume works even if the ledger is lost.

After the fix pushes, the token stays DRAFT and re-enters the loop until green. **Bound retries
(~3)**; past that, escalate (`escalation-and-signout.md`) rather than loop forever.

## Rate limits — inspect → classify → re-run (NEVER blind-fix)

Two distinct limits hit a long batch. They have **different** remedies; conflating them wastes quota
and masks real bugs.

### (1) The orchestrator's own GitHub API limit

Authenticated: 5000 req/hr core + a separate GraphQL pool — caused by **you** polling too hard, not
by any PR. Check headroom proactively:

```bash
gh api rate_limit --jq '{core: .resources.core.remaining, reset_in_s: (.resources.core.reset - now | floor)}'
```

**Remedy = slow down:** widen the CI-poll interval (toward the ~600s upper bound), batch `gh` calls
(one `gh pr view --json statusCheckRollup` per PR per loop), and trust the ledger instead of
re-listing each loop. If `core` is near 0, **stop polling until reset** (`ScheduleWakeup` for
`reset_in_s + 30`). Never spin on a 403/429.

### (2) Actions-side limits inside the runner (surface as JOB failures)

Symptoms in a failed job's log: image-registry pull throttling (Docker Hub / GHCR), `429` /
`API rate limit exceeded` from a step that calls the GitHub API (SARIF upload, `gh` in a step), or
concurrent-job/runner-minute caps queueing or cancelling jobs.

**Protocol — ALWAYS inspect before re-running:**

1. **Inspect** the failed check's log **in a delegated short-lived subagent, not inline** — hand it
   `gh pr checks <PR> | grep -i fail` + `gh run view <run-id> --log-failed` and have it return ONLY
   the one-line classification; the raw log stays out of the orchestrator's context (SKILL.md
   § Lean orchestrator / context hygiene).
2. **Classify.** _Transient_ (re-run, don't fix): `rate limit`, `429`, `toomanyrequests`,
   `TLS handshake timeout`, `i/o timeout`, `connection reset`, `pull access ... denied` after a
   throttle, a job `cancelled` by a concurrency cap. _Real_ (test/lint/build/scan finding): wake the
   subagent — re-running just re-fails and burns quota.
3. **Act on transient** — first confirm you're not _currently_ limited (`gh api rate_limit`; wait
   out the window), then `gh run rerun <run-id> --failed`. Bound to ≤2 re-runs/PR (log
   `rerun_count`); if it keeps failing the same way, escalate.
4. **Reduce recurrence:** ratchet `max_in_flight` down during a throttle; the merge-paced pipeline
   (one merge → one promote → one dispatch) naturally rate-limits new workflow runs.

**Golden rule:** a re-run is only valid for a _confirmed-transient_ failure. Inspect first; never
blind-retry a red check.

## `ScheduleWakeup` cadence

- **CI_POLL** — while any PR has running checks, **adapt the interval to observed CI duration**,
  don't hard-code it, **because** a fixed number either burns quota (too short) or lets green sit
  (too long). Learn the run length from the `ci_time` metric and aim to wake ~3–5 times per run:
  - rough rule: `poll ≈ clamp(observed_ci_time / 4, 30s, 600s)`;
  - short pipeline (~2-min unit-only) → poll near the **30s floor**; long one (~20-min
    integration/deploy) → ~300–600s;
  - on the **first** PR you have no `ci_time` yet — start ~120s, then recalibrate. If you can read an
    in-progress ETA (`gh run view` timing), bias toward "wake shortly after expected completion."
  - Tighten when a PR is _expected_ green imminently (front of the train); relax when nothing is
    close; back off if `rate_limit` headroom drops.
- **STUCK_RECHECK** — for BLOCKED tokens, piggyback on CI_POLL; if only blocked work remains,
  `1200s`.
- **IDLE_FALLBACK** — nothing actionable but work outstanding: `1200s–1800s`.
- **STOP** — backlog empty AND nothing in flight: don't reschedule; emit the final status table.
