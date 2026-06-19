---
name: resolve-open-issues
description: Use when asked to resolve many GitHub issues end-to-end as one focused PR each (e.g. "fix all open issues", "work the backlog"), especially when issues cluster on shared files and the run spans hours/CI. Provides a throttled draft→ready PR pipeline, a concurrency dial, wall-clock metrics, conflict-cluster serialization, a stuck/escalation+resume protocol, and crash-recoverable state.
---

# Resolve Open Issues — batch PR pipeline

A supervising **orchestrator** drives many GitHub issues to merge, **one focused PR per
issue** (or one PR per tightly-coupled bundle), by dispatching one **worker subagent** per
issue and metering them through a bounded draft→ready→merged pipeline.

This skill is the operating system for that batch: the policy, the state machine, the
timers, the metrics, the concurrency dial, and the escalation protocol. The two prompt
templates it references (`prompts/orchestrator.md`, `prompts/subagent-issue.md`) are the
repeatable, parameterized prompts — edit those, not ad-hoc copies.

> Origin: distilled from a live 32-issue run on `e2e-ministack` (2026-06-19). The pilot
> (#3, #4) validated the worker contract before scaling. Captured clarifications from the
> requesting user are embedded below as **AUTHORITATIVE CONFIG** — they are defaults, and
> the concurrency dial is how you deviate.

---

## 1. Roles (never blur these)

- **Orchestrator** (you, the main agent): owns the pipeline. Dispatches workers, polls CI,
  promotes draft→ready, rebases, merges/closes, refills, keeps the ledger + metrics,
  handles escalations. Stays in the loop across wakeups. Does NOT write issue fixes itself.
- **Worker subagent** (one per issue, `run_in_background: true`): root-cause → worktree →
  TDD → local gates → commit/push → **DRAFT PR** → report, then **STOP**. A worker NEVER
  marks ready, NEVER polls CI, NEVER closes issues, NEVER touches files outside its issue's
  scope, NEVER removes its worktree. If blocked, it escalates (§7) and stops.

This split is what makes the cap enforceable: only one actor (the orchestrator) ever
counts slots, so there's no race on "how many are ready."

---

## 2. AUTHORITATIVE CONFIG (captured clarifications — the `balanced` default)

These are the requesting user's decisions. They define the `balanced` profile. The
concurrency dial (§5) changes them deliberately; absent a reason, use these.

- **Pipeline caps:** ≤ **3** PRs in *ready-for-review* at once, plus ≤ **2** in *draft* =
  ≤ **5** in flight total.
- **Worker contract:** stop at draft PR + report (§1). Orchestrator promotes.
- **Conflict policy:** *parallel-with-rebase-at-merge*. Open PRs in parallel; rebase
  same-file PRs one-by-one as they merge. **Serialize the *ready* state within hot
  clusters** (only one PR from a given shared-file cluster is "ready" at a time) to cut
  rebase thrash.
- **Folding:** OK to combine tightly-coupled issues into one PR **only** when the review is
  simple and obvious (e.g. "add concurrency + timeout + npm-cache to every workflow job").
  Annotate every folded issue and the supervising agent. Prefer one-PR-per-issue otherwise.
- **Identity:** issue claims + PR authorship under the gh login; each worker's public,
  traceable identity is `claude-agent:issue-N`. The remote branch + draft PR are themselves
  state signals for other workers / supervisors.
- **Escalation:** blocked workers post questions publicly under their identity and stop;
  humans answer by addressing that identity; the orchestrator resumes (§7).
- **Durability:** keep a crash-recoverable ledger (§8). Refine this skill during the run.

---

## 3. Pipeline state machine

Each issue is a token moving through states. The orchestrator advances tokens on each loop.

```
            dispatch                 gates green + PR              CI all-green AND
 BACKLOG ───────────────▶ BUILDING ───────────────▶ DRAFT ─────────────────────────▶ READY
    ▲                        │ blocked                  │ ci red          ready_count<cap
    │ refill                 ▼                           ▼                              │
    │                     BLOCKED ◀────────────────── (worker fixes) ◀── orchestrator   │ approve+merge
    │  human answers addressing claude-agent:issue-N      pushes fix                     ▼
    └──────────────────────── resume (warm/cold) ◀──────────────────────────────────  MERGED ──▶ close issue
```

- **BACKLOG** — ordered, not yet dispatched.
- **BUILDING** — a worker is active (counts against `max_building`/draft slots).
- **DRAFT** — PR open, worker reported & stopped; CI running. Still a build/draft slot.
- **BLOCKED** — worker escalated (§7); **parked, frees its slot**, awaits a human answer.
- **READY** — CI green + promoted by orchestrator (counts against `max_ready`).
- **MERGED** — approved & merged; frees a ready slot, advances `main`, triggers the
  rebase+refill cascade (§6), then the issue is closed.

Slot accounting (balanced): `building+draft ≤ max_draft(2)` gates new dispatches;
`ready ≤ max_ready(3)` gates promotions; `in_flight ≤ 5` is the global ceiling. BLOCKED
tokens do not count.

---

## 4. The orchestrator loop (run every wakeup)

1. **Reconcile** — `gh pr list --state open` + read ledger. Reconstruct each token's state
   (cheap, idempotent — survives crashes). Stamp `now=$(date +%s)`.
2. **Collect worker reports** — for any finished background worker, record
   PR#/branch/worktree/gates/`draft_at`; mark DRAFT (or BLOCKED if it escalated).
3. **Poll CI** — for each DRAFT/READY PR: `gh pr checks <url>`. On all-green that wasn't
   green before, stamp `ci_green_at`. On red: dispatch a fix (warm-resume the worker, or a
   fresh worker) scoped to the failure; do NOT promote.
4. **Promote** (draft→ready) — for each green DRAFT, **in cluster-priority order**, if
   `ready_count < max_ready` AND no other PR from its hot cluster is already READY:
   `gh pr ready <url>`, stamp `ready_at`, and post the sequencing annotation (§6). Increment
   ready_count.
5. **Merge watch** — for READY PRs that got approved/merged (human or policy): stamp
   `merged_at`, **close the issue** with an acceptance-point summary, free the ready slot,
   then run the **rebase+refill cascade** (§6).
6. **Escalations** — for BLOCKED tokens, scan the issue/PR thread for a human reply
   addressing `claude-agent:issue-N` (§7). If found, resume.
7. **Refill** — while `building+draft < max_draft` and backlog non-empty: pick the next
   issue (cluster-spread; hot clusters one-at-a-time), dispatch a worker (§ template).
8. **Metrics + ledger** — recompute (§ below), write ledger (§8).
9. **Reschedule** — pick the next wake (§ timers) via `ScheduleWakeup`, or stop if backlog
   empty AND nothing in flight (then emit the final per-PR status table).

---

## 4a. CI monitoring & the green-gate (baked-in)

A PR is **never** promoted on elapsed time — only on **all-green CI** while a ready slot is
free. The monitor is a re-check loop owned by the orchestrator; the subagent owns fixes.

**Mechanism (who does what):**
- Background subagents **cannot self-schedule** a wakeup — a worker runs, comes to rest, and
  notifies the orchestrator. `ScheduleWakeup` is an orchestrator (main-loop) capability.
  Therefore: **orchestrator schedules the re-check; subagent performs any fix.**
- Each loop, for every DRAFT/READY PR, read `gh pr checks <url>` (or the
  `statusCheckRollup`). Classify:
  - **all-green** (0 failed, 0 pending; `skipping` is fine — e.g. fuzz is skipped on PRs) →
    stamp `ci_green_at`; promote if slot-free (§4 step 4).
  - **pending** (any check not COMPLETED) → do nothing yet; ensure a CI_POLL wakeup is set
    (`270s`, cache-warm) and re-check next loop.
  - **red** (any FAILURE/CANCELLED/TIMED_OUT) → **classify before acting** (§4b). A *transient*
    failure (rate-limit / network) is re-run, NOT fixed; a *real* failure wakes the subagent.
    Do NOT promote either way.
- **Waking the subagent on red:**
  - *Warm resume* — if the worker's `agentId` is still live & recent (persisted in the
    ledger), `SendMessage` to it with the failing check name + its log tail and "fix on your
    existing branch/worktree, push, then report." Cheapest; keeps its context.
  - *Cold resume* — after a crash/long gap (agentId lost), dispatch a **fresh** worker with
    the per-issue prompt + "branch/worktree/PR `fix/issue-N-*` already exist — resume there,
    do not recreate," plus the failing-check detail. The public PR thread + ledger are the
    source of truth that makes this possible.
  - After the fix pushes, CI re-runs; the token stays DRAFT and re-enters this loop until
    green. Bound retries (e.g. 3) — past that, escalate (§7) rather than loop forever.
- **Why not let the worker poll its own CI before stopping?** It would hold a subagent alive
  ~15–30 min busy-waiting, burning its context window for no work. The worker stops at
  draft; the orchestrator's single timer covers *all* open PRs at once. (Optional: a worker
  MAY do **one** quick post-push check to catch instant lint/unit breaks, then stop — but it
  must not loop.)

This is the loop your run depends on: *monitor for all-green; if not green, schedule a later
wakeup and re-check; if red, classify (§4b) then re-run-or-fix.*

---

## 4b. Rate limits — inspect → classify → re-run (NOT blind-fix)

Two distinct limits hit a long batch. They have **different** remedies; conflating them
wastes quota and masks real bugs.

### (1) The orchestrator's own GitHub API limit (`gh` / REST / GraphQL)
- Authenticated limit is 5000 req/hr (core) + a separate GraphQL pool. Caused by **you**
  polling too hard, not by any PR.
- **Check headroom proactively** before/while polling:
  `gh api rate_limit --jq '{core: .resources.core.remaining, reset_in_s: (.resources.core.reset - now | floor)}'`
- **Remedy = slow down:** widen the CI-poll interval (270s → 600s+), batch `gh` calls (one
  `gh pr view --json statusCheckRollup` per PR per loop, not per-check), prefer one combined
  query over many small ones, and don't re-list everything each loop — trust the ledger.
- If `core_remaining` is near 0, **stop polling until `reset_in_s` elapses** (ScheduleWakeup
  for `reset_in_s + 30`). Never spin on a 403/429.

### (2) Actions-side limits inside the runner (surface as JOB FAILURES, not API errors to you)
Symptoms in a failed job's log: image-registry pull throttling (Docker Hub / GHCR pulling the
MiniStack digest), `429 Too Many Requests` / `API rate limit exceeded` from a step that calls
the GitHub API (e.g. a SARIF upload, `gh` inside a step), or concurrent-job/runner-minute
caps queueing or cancelling jobs.

**Protocol — ALWAYS inspect before re-running:**
1. **Inspect the log** of the failed check. Get the run + failed job, then read the failing
   step:
   ```
   gh pr checks <PR> | grep -i fail
   gh run view <run-id> --log-failed        # or: gh run view --job <job-id> --log
   ```
2. **Classify the root cause:**
   - **Transient (rate-limit / network / registry throttle / runner flake)** → re-run. Tells:
     `rate limit`, `429`, `toomanyrequests`, `TLS handshake timeout`, `i/o timeout`, `connection
     reset`, `pull access ... denied` *after* a throttle, a job `cancelled` by a concurrency cap.
   - **Real (test/lint/build/scan finding)** → NOT a rate limit. Wake the subagent (§4a) to fix
     the actual failure. Re-running will just fail again and burn quota.
3. **Act on transient — re-run only the failed jobs, after the window resets:**
   - First confirm you're **not currently being limited** (re-running into an active limit just
     re-fails): re-check `gh api rate_limit`; for Actions/registry throttles, wait out the
     window (minutes) before retrying.
   - `gh run rerun <run-id> --failed` (re-runs only failed jobs, not the whole workflow —
     cheaper, faster, less load). Bound retries (e.g. ≤2 transient re-runs per PR); if it keeps
     failing the same way, escalate (§7) — it may not actually be transient.
   - Log the re-run in the ledger (`rerun_count`) so silent infinite-retry can't hide.
4. **Reduce recurrence:** stagger work to ease Actions load — lean toward the `serial` dial
   (§5) during a throttle, keep fewer PRs triggering CI at once, and let the merge-paced
   pipeline (one merge → one promote → one dispatch) naturally rate-limit new workflow runs.

**Golden rule:** a re-run is only valid for a *confirmed-transient* failure. Inspect first;
never blind-retry a red check.

---

## 5. The MERGE-TRAIN model + concurrency dial

**Primary model (preferred): a merge-train.** Serialize the *merge* stage, parallelize the
*build* stage wide. Concretely:
- **Widen the DRAFT funnel** — the real throughput dial is the number of *outstanding* PRs
  (drafts building/awaiting CI), up to `max_draft` (≈4), possibly bounded by the account's
  per-user open-PR cap. Workers build many issues' PRs in parallel as drafts.
- **Keep exactly ONE PR "Ready for Review" at a time** — the *front of the train*: rebased
  onto the latest `main` and all-green. `max_ready = 1`.
- **Train cycle:** front PR merges → `main` advances → pick the next draft → **rebase it onto
  the new `main` → wait for all-green → flip it Ready → it merges** → repeat. Because only one
  PR rebases-and-merges at a time, each lands against the *final* tree → near-zero thrash,
  while builds stay fully parallel behind it.
- **Who merges the front PR:** if branch protection + required checks are configured, arm
  GitHub **native auto-merge** (`gh pr merge <pr> --auto --squash`) — server-side, merges on
  green, no polling, survives your session (this IS the externalized "merger-agent"; a
  self-waking in-harness merger isn't possible — background agents can't `ScheduleWakeup`). If
  branch protection is absent, the orchestrator merges the front PR itself once it's green.

| knob                    | `serial`     | `merge-train` (default) | `aggressive`        |
|-------------------------|--------------|-------------------------|---------------------|
| `max_draft` (building)  | 1            | 4 (or per-user PR cap)  | 6                   |
| `max_ready`             | 1            | **1** (train front)     | 2                   |
| `max_in_flight`         | 2            | 5                       | 8                   |
| merge gating            | one-at-a-time| **train: rebase→green→merge front, repeat** | parallel+rebase |
| folding                 | aggressive   | coupled-trivial only    | minimal             |
| CI-poll interval        | 270s         | 270s                    | 270s                |

**Ratchet DOWN toward `serial` when:** rebases exceed ~2/PR, CI failures cluster, a rate-limit
throttle is active (§4b), or the human wants careful sequential review.

**Ratchet UP (wider draft funnel) when:** the box is idle, CI passes first-try consistently,
remaining issues touch independent files, and **review/merge latency is the long pole** —
keep more drafts pre-built and green so the train front is never starved.

The dial is a per-loop decision: read the metrics (§8), pick the profile, proceed. The
merge-train's `max_ready=1` is what makes "one is kept Ready if all-green, merges, then the
next is rebased and promoted" the steady-state behavior.

---

## 6. Sequencing, rebase & refill cascade

Hot clusters (PRs editing the same file) merge cleanly only one at a time. On every merge:

1. **Identify the next same-cluster PR** (by ledger cluster tag, cluster-priority order).
2. **Rebase it onto the new `main`:** in its worktree —
   `git fetch origin && git rebase origin/main`. On conflict, the orchestrator resolves
   minimally (the change is small + known) or warm-resumes the worker to resolve; push
   `--force-with-lease`.
3. **Re-run local gates** on the rebased branch (cheap unit tier). If green, it's
   promotion-eligible.
4. **Refill:** the merge freed a ready slot and (usually) a build slot — dispatch the next
   backlog issue to keep `building+draft` at the cap.

**Sequencing annotation — post on the PR, mirror to the issue.** The human reviews on the
**PR**, so the merge order MUST live there; do not make them infer it from PR-number
recency (recency ≠ merge order — order is driven by file-conflict *clusters*, not creation
time). When a PR is promoted to ready, post a **"🔀 Merge guidance (for the reviewer)"**
comment on the PR stating, in plain terms:
- whether it's **independent / safe to merge now** (touches files no other open PR touches),
  or **must follow** another PR (name it) and be **rebased after** it merges;
- its **cluster**, its **position** in that cluster's merge order, and the PRs queued behind
  it — e.g. *"Cluster A (workflows). Merge order: #38 → #41 → #44. This is #41; rebase onto
  main after #38 merges."*;
- a one-line action for the reviewer ("review on its merits; no PR needs to merge first").

Two PRs in **different** clusters (disjoint files) have **no** ordering constraint — say so
explicitly. Two PRs in the **same** cluster merge in sequence (each rebases on the prior).
Mirror the cross-cutting note onto the **issue** too, so a supervisor can rebuild the plan
after a crash.

---

## 7. Stuck → escalate → resume protocol

When a worker hits an ambiguity it cannot resolve within its issue's scope (a design
choice, conflicting acceptance criteria, a missing decision, an unexpected blocker):

**Worker side (escalate, then stop):**
1. Post a comment on the **issue**, opening with its identity and a clear BLOCKED marker,
   then numbered questions:
   `🤖 claude-agent:issue-N — BLOCKED, need clarification:` + the questions + what it tried.
2. If a draft PR already exists, post the **same** questions on the PR, cross-linking the
   issue comment (so the question is visible wherever a human looks).
3. Report `STATE: BLOCKED` + the verbatim questions to the orchestrator and **STOP**. Do
   not guess outside scope.

**Orchestrator side (park + free slot):**
4. Mark the issue BLOCKED in the ledger; record the questions and the worker's
   branch/worktree/PR. BLOCKED frees the build slot (don't count it) → refill from backlog.

**Human side (the signal):**
5. The human answers by replying in the issue **or** PR thread, **addressing the agent
   identity** — a comment beginning `@claude-agent:issue-N` (or `claude-agent:issue-N:`)
   with the answers. Addressing the identity *is* the resume signal.

**Orchestrator side (detect + resume):**
6. The STUCK_RECHECK timer scans BLOCKED issues' threads for a reply addressing
   `claude-agent:issue-N`. On finding one, resume:
   - **Warm resume** (preferred if the worker's agentId is still live & recent): SendMessage
     to that agentId with the answer + "continue to draft from your existing branch/PR."
   - **Cold resume** (after a crash/long gap): dispatch a *fresh* worker with the original
     per-issue prompt **plus** the Q&A and "your branch/worktree/PR `fix/issue-N-*` already
     exist — resume from there, do not recreate." Cold resume is why the public thread is
     the source of truth: it survives losing the agentId.
7. The resumed worker incorporates the answer, finishes to draft, reports; the token
   re-enters the pipeline at DRAFT. Unpark.

---

## 7b. Terminal sign-out + auto-close verification (don't strand or double-dispatch)

**Problem:** "issue OPEN + a `working on it` claim comment" is ambiguous — actively-working /
parked-at-draft / blocked / **crashed mid-task** all look identical. A supervisor or a free
worker then either skips a pickable issue or double-dispatches a live one. Fix = an
unambiguous **terminal sign-out** as the worker's last public act, plus orchestrator
verification that the issue will actually close.

**Worker sign-out (the worker's FINAL action before it stops, posted on the issue under its
identity):** `🤖 claude-agent:issue-N — signing out, over and out.` followed by its terminal
state, exactly one of:
- **DONE/DRAFT** — "PR #X opened (draft); body uses `Closes #N` so the issue auto-closes on
  merge. No longer actively working — now in the orchestrator's review pipeline." (Parked, do
  NOT redispatch.)
- **BLOCKED** — "blocked on the questions above (§7); not working until answered." (Parked
  awaiting human; do NOT redispatch — it resumes via §7.)
- **ABANDONED** — "could not complete: <reason>. No PR / PR not viable. **Issue is free for
  pickup.**" (Explicitly redispatchable.)

**Is a closing comment necessary?** For *closure mechanics*, **no** — when the PR's body
carries a closing keyword (`Closes/Fixes/Resolves #N`), merging auto-closes the issue and
leaves a "Closed via #X" trace; a separate "closing" comment is redundant. What *does* have
independent value is the **acceptance-point summary** posted at promotion (maps each issue
criterion to the change — for the human reviewer), and the **sign-out** (for coordination).
Keep those two; don't add a third hand-closing comment when auto-close is wired.

**Orchestrator — verify, don't assume (every loop, for each ready/merged PR):**
- Confirm the auto-close link exists:
  `gh pr view <PR> --json closingIssuesReferences --jq '[.closingIssuesReferences[]?.number]'`.
  - **Non-empty** → the issue WILL auto-close on merge; do nothing manual.
  - **Empty (PR only *references* the issue)** → it will NOT auto-close. Either edit the PR
    body to add `Closes #N` (preferred), or on merge **manually close** the issue with a
    one-line *proposed-closure* comment citing the merged PR. Never leave a resolved issue
    silently open — that's the state that makes a supervisor think work is still in flight.
- **Pickup rule:** an issue is redispatchable iff it is OPEN **and** (no live worker owns it)
  **and** (its latest sign-out is ABANDONED, or there is a claim comment but NO sign-out and
  the worker is not live = crashed). Never redispatch an issue whose sign-out is DONE/DRAFT or
  BLOCKED.

---

## 8. Metrics (real wall-clock) + crash-recoverable ledger

Stamp epochs with `date +%s` (the orchestrator is the main agent — real clock allowed;
note that Workflow *scripts* forbid `Date.now()`, this skill does not use them). Per issue
record: `dispatched_at, claimed_at, draft_at, ci_green_at, ready_at, merged_at`.

**Derived (seconds → minutes for the ledger):**
- `build_time = draft_at − dispatched_at` (worker speed)
- `ci_time = ci_green_at − draft_at` (CI duration — usually the long pole)
- `review_latency = merged_at − ready_at` (human merge wait)
- `lead_time = merged_at − dispatched_at` (end-to-end)

**Batch-level:** `throughput = merged / ((now − BATCH_START)/3600)` (PRs/hr), live `WIP`
(in-flight count), `rebase_count`, `blocked_count`. Use these to drive the dial (§5):
high `review_latency` ⇒ don't add build parallelism; high `rebase_count` ⇒ ratchet down.

**Ledger** lives at the project's session-memory file (here `.remember/remember.md`) and is
the crash spine — a fresh session reconstructs in-flight state from it + the issue/PR
annotations. It MUST hold: roles/identity, the active profile + caps, the skip list, the
conflict clusters, the ordered backlog, the per-issue STATUS table (state + the 6 epoch
stamps + PR#/branch/worktree/cluster), blocked questions, and "next action on resume."

---

## 9. Timers (ScheduleWakeup cadence)

- **CI_POLL** — while any PR has running checks: `270s` (stays inside the 5-min prompt-cache
  TTL; polling a ~15–30 min CI run every 270s is the sweet spot).
- **PROMOTE/MERGE_WATCH** — folded into each wake's loop (§4 steps 4–5).
- **STUCK_RECHECK** — for BLOCKED tokens: piggyback on CI_POLL; if only blocked work
  remains, `1200s`.
- **IDLE_FALLBACK** — nothing actionable but work outstanding: `1200s–1800s`.
- **STOP** — backlog empty AND nothing in flight: don't reschedule; emit final status table.

Don't pick 300s (worst of both — pays the cache miss without amortizing it).

---

## 10. Gotchas (learned, don't relearn)

- **mise PATH in git hook subprocesses:** the repo's pre-commit *local* hooks shell out to
  the pinned `npm`; git's hook subprocess may not inherit the mise PATH, so `git commit`
  fails with "Executable `npm` not found" even though `pre-commit run` passed directly.
  Fix: export PATH **in the same shell invocation** as `git commit` (workers are told this).
- **semgrep PostToolUse hook** errors "No SEMGREP_APP_TOKEN" on every Write/Edit — it fires
  *after* the write, so the file is still created; it's auth-missing noise, not a finding.
  Don't chase it; flag it once.
- **Worktrees branch from `origin/main`**, not the current canonical-root branch — verify
  the base HEAD when a worker reports a surprising base.
- **`needs:` doesn't imply a fork guard** — a downstream job inherits dependency ordering,
  not the upstream job's `if:`. Guard the socket-mounting job directly.

---

## 11. Repeatable prompts

- `prompts/orchestrator.md` — the top-level supervisor prompt (original instructions +
  embedded clarifications). Paste to re-run the whole batch.
- `prompts/subagent-issue.md` — the parameterized per-issue worker prompt (`{{PLACEHOLDERS}}`).
  The orchestrator fills it per issue. Includes the report-back schema + the §7 escalation.

To re-run from scratch: read this SKILL, adopt `balanced`, seed the ledger from
`gh issue list --state open`, then run the loop (§4).
