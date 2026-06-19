---
name: resolve-open-issues
description: Use to autonomously resolve, fix, or close MULTIPLE open GitHub issues in one run — driving each from issue to merged PR without per-issue hand-holding. Trigger whenever the user points at issues in the plural or a whole tracker rather than one named bug: "fix all the open issues," "knock out / burn down / clear / work the backlog," "go through every issue and open a PR each," "resolve #3 #4 #9, one PR per issue," "spin up agents to work my issues overnight," "draft → green → merge → next until empty," "keep the PRs moving through CI as they go green," "work the issues on owner/repo." The defining signal is many issues plus an end-to-end loop (fix → open PR → pass CI → merge → take the next), often long-running, unattended, or spanning many PRs at once. Do NOT use for a single bug fix, reviewing or merging one already-open PR, rebasing one branch, or debugging why CI is red.
---

# Resolve Open Issues — batch PR pipeline

A supervising **orchestrator** drives many GitHub issues to merge, **one focused PR per
issue** (or one PR per tightly-coupled bundle), by dispatching one **worker subagent** per
issue and metering them through a bounded draft→ready→merged pipeline.

This skill is the operating system for that batch: the policy, the state machine, the
timers, the metrics, the concurrency dial, and the escalation protocol. The two prompt
templates it references (`prompts/orchestrator.md`, `prompts/subagent-issue.md`) are the
repeatable, parameterized prompts — edit those, not ad-hoc copies.

> The operating model is a **merge-train** (§5): build many PRs in parallel as drafts, keep
> exactly one "Ready for Review" at the train front (rebased onto latest `main`, all-green),
> merge it, advance, promote the next. The open-PR width is an **injected launch parameter**
> with an adaptive ratchet (§5a). The config below is authoritative; the dial (§5) is how you
> deviate per loop.
>
> **Before your first dispatch, skim §10 (Gotchas)** — the mise-PATH and semgrep-hook quirks
> there will otherwise read as real failures and cost you a debugging detour. The two
> paste-ready prompts live in §11.

---

## 1. Roles (never blur these)

- **Orchestrator** (you, the main agent): owns the pipeline. Dispatches workers, polls CI,
  promotes draft→ready, rebases, merges/closes, refills, keeps the ledger + metrics,
  handles escalations. Stays in the loop across wakeups. Does NOT write issue fixes itself.
- **Worker subagent** (one per unit of work — usually one issue, sometimes a folded bundle;
  `run_in_background: true`): root-cause → worktree → TDD → local gates → commit/push →
  **DRAFT PR** → report, then **STOP**. A worker NEVER marks ready, NEVER polls CI, NEVER closes
  issues, NEVER touches files outside its scope, NEVER removes its worktree. If blocked, it
  escalates (§7) and stops.

This split is what makes the cap enforceable: only one actor (the orchestrator) ever
counts slots, so there's no race on "how many are ready."

---

## 2. AUTHORITATIVE CONFIG

The operating defaults. The concurrency dial (§5) changes them deliberately; absent a reason,
use these.

- **Pipeline caps (merge-train):** start with **1** PR in _ready-for-review_ (`max_ready = 1`,
  the train front), plus a _draft funnel_ of `max_in_flight − max_ready`. **`max_in_flight` is
  injected at launch** (`--max-in-flight`, default **3**, ceiling **1000**); both `max_ready`
  and `max_in_flight` adapt via the ratchet (§5a) — `max_ready` may grow beyond 1 when the
  train runs smoothly (speed matters). Total open PRs never exceed `max_in_flight`.
- **Worker contract:** stop at draft PR + report (§1). Orchestrator promotes.
- **Conflict policy:** _parallel-with-rebase-at-merge_. Open PRs in parallel; rebase
  same-file PRs one-by-one as they merge. **Serialize the _ready_ state within hot
  clusters** (only one PR from a given shared-file cluster is "ready" at a time) to cut
  rebase thrash.
- **Folding:** **combine** tightly-coupled issues into one worker/PR when they share a concern
  and a reviewer can take them in a single scope (e.g. "add concurrency + timeout + npm-cache to
  every workflow job", or a fix plus its entailed test/doc). This is encouraged — it cuts review
  and rebase overhead. Fold decisions are made in **Phase 0 triage** (§4); annotate every folded
  issue + the supervising agent. When a reviewer wouldn't obviously want them together, keep them
  one-PR-per-issue.
- **Identity:** issue claims + PR authorship under the gh login (`{{GH_LOGIN}}` from
  `gh api user --jq .login`). Each worker's public, traceable identity is **`@<gh-login>
(agent:wK)`** — where `wK` is a **sequential handle the orchestrator hands out at dispatch**
  (`w1`, `w2`, …), NOT tied to an issue number, because one worker may cover several folded
  issues (§ Folding). The greppable resume token is `agent:wK`. The worker states which
  issue(s) it covers in its claim (e.g. `@scottschreckengaust (agent:w3) — issues #11, #20`).
  The remote branch + draft PR are themselves state signals for other workers / supervisors.
- **Escalation:** blocked workers post questions publicly under their identity and stop;
  humans answer by addressing that identity; the orchestrator resumes (§7).
- **Durability:** keep a crash-recoverable ledger (§8). Refine this skill during the run.

---

## 3. Pipeline state machine

Each issue is a token moving through states. The orchestrator advances tokens on each loop.

```text
   dispatch      gate+PR        CI green & slot      approve + merge
BACKLOG ─────▶ BUILDING ─────▶ DRAFT ─────────────▶ READY ─────────────▶ MERGED ─▶ close issue
                  │              ▲                                          │
         blocked  │              │ ci red: worker pushes fix, back to DRAFT │ frees a slot
                  ▼              │                                          │
               BLOCKED ─────────▶ (resume, warm/cold)                      ▼
                  ▲                                                    refill BACKLOG
                  └─ human answers @<login> (agent:wK)
```

- **BACKLOG** — ordered, not yet dispatched.
- **BUILDING** — a worker is active (counts against the `max_draft` funnel).
- **DRAFT** — PR open, worker reported & stopped; CI running. Still a build/draft slot.
- **BLOCKED** — worker escalated (§7); **parked, frees its slot**, awaits a human answer.
- **READY** — CI green + promoted by orchestrator (counts against `max_ready`).
- **MERGED** — approved & merged; frees a ready slot, advances `main`, triggers the
  rebase+refill cascade (§6), then the issue is closed.

Slot accounting: `building+draft ≤ max_draft` gates new dispatches; `ready ≤ max_ready` gates
promotions; `in_flight ≤ max_in_flight` is the global ceiling. All three derive from the
injected `--max-in-flight` (§2, §5a): `max_draft = max_in_flight − max_ready`. BLOCKED tokens
do not count.

---

## 4. The orchestrator loop (run every wakeup)

**Phase 0 — Triage & cluster (run ONCE at startup; refresh when the backlog changes).** This is
where folding and cluster assignment are decided, before any dispatch:

1. List the work: `gh issue list --state open` (or the injected `[ISSUE_NUMBERS]`).
2. For each issue, note the **files/area it will most likely touch** (from its text + a quick
   look at the cited code). Group issues that touch the **same file(s) or subsystem** into a
   named **cluster** (e.g. "workflows", "stack+snapshot"). Issues in different clusters are
   independent and merge in any order; issues in the same cluster must be **serialized** at the
   ready/merge stage (§6).
3. **Fold** issues into one worker/PR only when they are tightly coupled AND a reviewer can
   reasonably take them in a single scope — e.g. the same mechanical change across several files,
   or a fix plus its directly-entailed test/doc update. Folding is encouraged here, not avoided:
   it cuts review and rebase overhead when the shared concern is obvious. When unsure whether a
   reviewer would want them together, keep them separate. Record each fold (which issues → which
   worker) and annotate every folded issue.
4. Write the resulting **ordered backlog + cluster map + fold decisions** to the ledger (§8) so a
   crash can rebuild them. This map is what the loop's "cluster-priority order" (steps 4, 7)
   refers to.

**The loop (every wakeup):**

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
   addressing `agent:wK` (§7). If found, resume.
7. **Refill** — while `building+draft < max_draft` and backlog non-empty: pick the next
   issue (cluster-spread; hot clusters one-at-a-time), dispatch a worker (§ template).
8. **Metrics + ledger** — recompute (§ below), write ledger (§8).
9. **Reschedule** — pick the next wake (§ timers) via `ScheduleWakeup`, or stop if backlog
   empty AND nothing in flight (then emit the final per-PR status table).

---

## 4a. CI monitoring & the green-gate (baked-in)

A PR is **never** promoted on elapsed time — only on **all-green CI** while a ready slot is
free. Background subagents **cannot self-schedule** a wakeup, so `ScheduleWakeup` is the
orchestrator's job: **orchestrator schedules the re-check; subagent performs any fix.**

Each loop, for every DRAFT/READY PR, read `gh pr checks <url>` (or `statusCheckRollup`) and
classify:

- **all-green** (0 failed, 0 pending; `skipping` is fine — e.g. fuzz is skipped on PRs) → stamp
  `ci_green_at`; promote if slot-free (§4 step 4).
- **pending** → do nothing yet; ensure a CI_POLL wakeup is set (interval adapted to CI duration,
  §9) and re-check next loop.
- **red** (`FAILURE`/`CANCELLED`/`TIMED_OUT`) → **classify before acting** (§4b): a _transient_
  failure (rate-limit / network) is re-run, NOT fixed; a _real_ failure wakes the subagent.
  Don't promote either way.

**Waking the subagent on red** — _warm resume_ if its `agentId` is still live & recent (ledger):
`SendMessage` the failing check + log tail and "fix on your existing branch/worktree, push, then
report" (keeps its context). _Cold resume_ after a crash (agentId lost): dispatch a **fresh**
worker with the per-issue prompt + "branch/worktree/PR `fix/issue-N-*` already exist — resume
there, do not recreate" + the failing-check detail; the public PR thread + ledger are what make
this possible. After the fix pushes, the token stays DRAFT and re-enters this loop until green.
Bound retries (~3) — past that, escalate (§7) rather than loop forever.

A worker **does not poll its own CI** (it would busy-wait ~15–30 min, burning its context for no
work) — the orchestrator's single timer covers _all_ open PRs at once. (Optional: a worker MAY do
**one** quick post-push check to catch an instant lint/unit break, then stop — never loop.)

---

## 4b. Rate limits — inspect → classify → re-run (NOT blind-fix)

Two distinct limits hit a long batch. They have **different** remedies; conflating them
wastes quota and masks real bugs.

### (1) The orchestrator's own GitHub API limit (`gh` / REST / GraphQL)

Authenticated limit is 5000 req/hr (core) + a separate GraphQL pool — caused by **you** polling
too hard, not by any PR. Check headroom proactively:
`gh api rate_limit --jq '{core: .resources.core.remaining, reset_in_s: (.resources.core.reset - now | floor)}'`.
**Remedy = slow down:** widen the CI-poll interval (push toward the §9 upper bound, ~600s+),
batch `gh` calls (one
`gh pr view --json statusCheckRollup` per PR per loop), and trust the ledger instead of
re-listing each loop. If `core_remaining` is near 0, **stop polling until `reset_in_s` elapses**
(ScheduleWakeup for `reset_in_s + 30`). Never spin on a 403/429.

### (2) Actions-side limits inside the runner (surface as JOB FAILURES, not API errors to you)

Symptoms in a failed job's log: image-registry pull throttling (Docker Hub / GHCR), `429` /
`API rate limit exceeded` from a step that calls the GitHub API (SARIF upload, `gh` in a step),
or concurrent-job/runner-minute caps queueing or cancelling jobs.

**Protocol — ALWAYS inspect before re-running:**

1. **Inspect** the failed check's log:
   `gh pr checks <PR> | grep -i fail`, then `gh run view <run-id> --log-failed`.
2. **Classify.** _Transient_ (re-run, don't fix): `rate limit`, `429`, `toomanyrequests`, `TLS
handshake timeout`, `i/o timeout`, `connection reset`, `pull access ... denied` after a
   throttle, a job `cancelled` by a concurrency cap. _Real_ (test/lint/build/scan finding): wake
   the subagent (§4a) — re-running just re-fails and burns quota.
3. **Act on transient** — first confirm you're not _currently_ limited (`gh api rate_limit`;
   wait out Actions/registry windows), then `gh run rerun <run-id> --failed` (failed jobs only).
   Bound to ≤2 re-runs/PR (log `rerun_count`); if it keeps failing the same way, escalate (§7).
4. **Reduce recurrence:** ratchet `max_in_flight` down (§5a) during a throttle; the merge-paced
   pipeline (one merge → one promote → one dispatch) naturally rate-limits new workflow runs.

**Golden rule:** a re-run is only valid for a _confirmed-transient_ failure. Inspect first;
never blind-retry a red check.

---

## 5. The MERGE-TRAIN model + concurrency dial

**The model: a merge-train.** Serialize the _merge_ stage, parallelize the _build_ stage wide.
Concretely:

- **Widen the DRAFT funnel** — the real throughput dial is the number of _outstanding_ PRs
  (drafts building/awaiting CI), `max_draft = max_in_flight − max_ready`. Workers build many
  issues' PRs in parallel as drafts.
- **Keep a small "Ready for Review" front** — start with exactly ONE (`max_ready = 1`): the
  _front of the train_, rebased onto the latest `main` and all-green. `max_ready` may grow
  beyond 1 (§5a) when the train runs smoothly and conflicts are rare — a wider front trades a
  little rebase risk for merge throughput when speed matters.
- **Train cycle:** front PR merges → `main` advances → pick the next draft → **rebase it onto
  the new `main` → wait for all-green → flip it Ready → it merges** → repeat. Because the front
  rebases-and-merges in order, each lands against the _final_ tree → near-zero thrash, while
  builds stay fully parallel behind it.
- **Who merges the front PR:** if branch protection + required checks are configured, arm
  GitHub **native auto-merge** (`gh pr merge <pr> --auto --squash`) — server-side, merges on
  green, no polling, survives your session (this IS the externalized "merger-agent"; a
  self-waking in-harness merger isn't possible — background agents can't `ScheduleWakeup`). If
  branch protection is absent, the orchestrator merges the front PR itself once it's green.

Both `max_ready` and `max_in_flight` are **adaptive** (§5a), seeded from the injected launch
parameter. The dial below is the shape of how they move, not fixed profiles: ratchet toward
the left under stress, toward the right when the box is idle and CI is clean.

| knob            | under stress        | steady (default)          | wide-open                   |
| --------------- | ------------------- | ------------------------- | --------------------------- |
| `max_ready`     | 1                   | 1                         | 2–3 (smooth + low-conflict) |
| `max_in_flight` | floor 1–2           | injected `N` (default 3)  | up to ceiling 1000          |
| `max_draft`     | `in_flight − ready` | `in_flight − ready`       | `in_flight − ready`         |
| merge gating    | one-at-a-time       | train: rebase→green→merge | parallel + rebase           |
| folding         | aggressive          | coupled-trivial only      | minimal                     |

**Ratchet DOWN when:** rebases exceed ~2/PR, CI failures cluster, a rate-limit throttle is
active (§4b), or the human wants careful sequential review. (Drop `max_in_flight` first; only
drop `max_ready` to 1 if a wider front is causing rebase thrash.)

**Ratchet UP when:** the box is idle, CI passes first-try consistently, remaining issues touch
independent files, and **review/merge latency is the long pole** — widen the draft funnel so
the front is never starved, and (only if conflicts stay rare) grow `max_ready` so more than one
PR can be merge-ready at once.

The dial is a per-loop decision: read the metrics (§8), move a notch, proceed.

### 5a. `max_in_flight` / `max_ready` are launch-seeded + adaptive

The open-PR width is **set at launch by the human**, not discovered. The repo's
`settings/interaction_limits` "max open PRs per user" value is a GitHub **UI-only** control
with **no public REST/GraphQL endpoint** — `gh api repos/{o}/{r}/interaction-limits` returns
`{}` and `.../rulesets` returns `[]` even when the UI shows a number (verified). So the
orchestrator MUST NOT try to read it (and MUST NOT scrape the settings HTML — that needs a
browser session cookie, not the `gh` token). Instead:

- **Challenge the human at launch with their own interaction-limits page.** `--max-in-flight N`
  is an injected launch parameter. If the launch prompt provides it, use it as the **hard
  ceiling**. If it is **absent, ASK before dispatching** — and make the question concrete by
  pointing at the setting they'd read it from:

  > How many open PRs may I keep in flight at once? Your repo's per-user cap is on the settings
  > page — open `https://github.com/<owner>/<repo>/settings/interaction_limits` and use the
  > "maximum open pull requests per user" value there. (I can't read it via API — it's UI-only.)
  > Default **3** if you'd rather I just start conservative; ceiling is 1000.

- **Range `1..1000`** (1000 mirrors the GitHub UI's own max; there is no smaller built-in limit).
- **Adaptive ratchet (seed both from the answer):**
  - _`max_in_flight`_ — start at the injected `N` (default 3). While CI passes first-try AND
    `gh api rate_limit` core-remaining stays healthy (>1000), ratchet **UP by 1 each clean
    loop**, never past the ceiling. On ANY rate-limit signal — own-API limit (§4b‑1) or an
    Actions-side 429/throttle in a job log (§4b‑2) — ratchet **DOWN by 1** (floor 1) and widen
    the CI-poll interval.
  - _`max_ready`_ — start at **1**. Grow it (cap ~3) only when the train has been running
    smoothly: several consecutive clean merges, rebases averaging <1/PR, and remaining work
    spread across **disjoint** clusters (a wider front is safe only when fronts don't conflict).
    Shrink back to 1 the moment rebase thrash reappears. This is the "speed when smooth" lever.
  - **Log every change** in the ledger (`knob: old→new` + trigger) so a silent runaway can't hide.
- **Invariant:** `max_draft = max_in_flight − max_ready`, and total open PRs ≤ `max_in_flight`,
  at every width.

### 5b. Pilot mode vs. steady-state

**Steady-state** is just the normal operating mode: the §4 loop running every wakeup with the
adaptive ratchet (§5a) live — `max_in_flight` and `max_ready` free to move with the metrics.
That's the default and where the batch spends ~all its time.

**Pilot mode** is an _optional_ confidence gate for the very first run on an unfamiliar
repo/CI, where the only difference is: **hold the ratchet flat** (don't auto-widen) until the
first worker has gone fully BACKLOG→MERGED once. It exists because the first end-to-end pass is
what surfaces repo-specific surprises (a flaky gate, a slow CI tier, a missing permission) — and
you'd rather learn that at width 1–3 than mid-widening. Once one PR has merged clean, pilot mode
is over: **release the ratchet and you're in steady-state.** Skip pilot mode entirely (start
straight in steady-state) on a repo you've already run this on. Set `N=1` to make the pilot a
strict single-issue dry run.

**Thin backlog is fine, not a failure.** If fewer issues exist than `max_in_flight`, the train
just runs narrower — dispatch what's there, and the loop ends cleanly via the normal §9 STOP
condition ("backlog empty AND nothing in flight"). You never need to pad the cap to the issue
count; `max_in_flight` is a ceiling, not a quota. A 2-issue backlog with `N=3` simply means two
workers and an early, tidy finish.

### 5c. The merge-closer loop (the always-on "merger / reviewer / approver")

The train needs an engine that _keeps turning_ even when no worker is reporting: something that
watches the front PR, gets it green-and-merged, closes the issue, advances the train, and
refills — every wakeup, forever, until the backlog drains. That engine is the **orchestrator
itself** running its loop (§4) on the `ScheduleWakeup` cadence (§9); it is not a separate
subagent, because **only the main loop can self-schedule** — a background subagent can't wake
itself, so a "merger subagent" would run once and die. So the always-on merger == the
orchestrator's recurring loop. Its merge-closer responsibilities, every wakeup:

1. **Review/approve — know what your repo actually requires.** Check
   `gh api repos/{o}/{r}/branches/main/protection` once and cache it:
   - **No branch protection / no required reviews** (this repo today — returns `Branch not
protected`): no approval is needed to merge. The orchestrator merges the green front PR
     directly. There is nothing to "approve."
   - **Reviews required:** ⚠️ **a PR cannot be approved by its own author.** Every PR here is
     authored by your `gh` login, so **you cannot self-approve via the API** — GitHub rejects
     `gh pr review --approve` on your own PR (`422 Unprocessable`). Do not pretend to; surface
     it. Options the orchestrator should present rather than fake: (a) a human/second account
     approves, (b) relax the review requirement, or (c) use an admin merge if policy allows
     (`gh pr merge --admin`, admin-only, bypasses required reviews — log that it was used).
2. **Merge the green front PR.** Prefer **native auto-merge** so it survives your session and
   merges server-side the instant checks pass: `gh pr merge <pr> --auto --squash` (requires
   branch protection + required checks to be meaningful). If protection is absent, merge
   directly once green: `gh pr merge <pr> --squash`. Never merge a PR with red/pending checks.
3. **Close / reconcile the issue.** On merge, confirm the auto-close fired (§7b); for
   DONE-NO-CLOSE related issues, take the disposition the worker handed you (close as
   resolved-elsewhere, relabel, or re-scope).
4. **Advance + refill.** Run the rebase+refill cascade (§6): promote the next draft to the
   front, dispatch a new worker to keep the funnel at width. Then `ScheduleWakeup` again.

This is "constantly running" in the only way the harness allows: a durable, crash-recoverable
**loop** (the ledger §8 lets a fresh session resume it), not a daemon. If `max_ready > 1`, the
same loop simply maintains several merge-ready fronts at once.

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
recency (recency ≠ merge order — order is driven by file-conflict _clusters_, not creation
time). When a PR is promoted to ready, post a **"🔀 Merge guidance (for the reviewer)"**
comment on the PR stating, in plain terms:

- whether it's **independent / safe to merge now** (touches files no other open PR touches),
  or **must follow** another PR (name it) and be **rebased after** it merges;
- its **cluster**, its **position** in that cluster's merge order, and the PRs queued behind
  it — e.g. _"Cluster A (workflows). Merge order: #38 → #41 → #44. This is #41; rebase onto
  main after #38 merges."_;
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

- Post a comment on the **issue**, opening with its identity and a clear BLOCKED marker, then
  numbered questions:
  `🤖 @<login> (agent:wK) — BLOCKED, need clarification:` + the questions + what it tried.
- If a draft PR already exists, post the **same** questions on the PR, cross-linking the issue
  comment (so the question is visible wherever a human looks).
- Report `STATE: BLOCKED` + the verbatim questions to the orchestrator and **STOP**. Do not
  guess outside scope.

**Orchestrator side (park + free slot):**

- Mark the issue BLOCKED in the ledger; record the questions and the worker's
  branch/worktree/PR. BLOCKED frees the build slot (don't count it) → refill from backlog.

**Human side (the signal):**

- The human answers by replying in the issue **or** PR thread, **addressing the agent
  identity** — a comment containing the worker's `agent:wK` token (e.g. replying
  `@<login> (agent:wK): <answers>`). Addressing the `agent:wK` token _is_ the resume signal.

**Orchestrator side (detect + resume):**

- The STUCK_RECHECK timer scans BLOCKED issues' threads for a reply addressing
  `agent:wK`. On finding one, resume:
  - **Warm resume** (preferred if the worker's agentId is still live & recent): SendMessage to
    that agentId with the answer + "continue to draft from your existing branch/PR."
  - **Cold resume** (after a crash/long gap): dispatch a _fresh_ worker with the original
    per-issue prompt **plus** the Q&A and "your branch/worktree/PR `fix/issue-N-*` already
    exist — resume from there, do not recreate." Cold resume is why the public thread is the
    source of truth: it survives losing the agentId.
- The resumed worker incorporates the answer, finishes to draft, reports; the token re-enters
  the pipeline at DRAFT. Unpark.

---

## 7b. Terminal sign-out + auto-close verification (don't strand or double-dispatch)

**Problem:** "issue OPEN + a `working on it` claim comment" is ambiguous — actively-working /
parked-at-draft / blocked / **crashed mid-task** all look identical. A supervisor or a free
worker then either skips a pickable issue or double-dispatches a live one. Fix = an
unambiguous **terminal sign-out** as the worker's last public act, plus orchestrator
verification that the issue will actually close.

**Worker sign-out (the worker's FINAL action before it stops, posted on every issue it covers
under its identity):** `🤖 @<login> (agent:wK) — signing out, over and out.` followed by its terminal
state, exactly one of:

- **DONE/DRAFT** — "PR #X opened (draft); body uses `Closes #N` so the issue auto-closes on
  merge. No longer actively working — now in the orchestrator's review pipeline." (Parked, do
  NOT redispatch.)
- **BLOCKED** — "blocked on the questions above (§7); not working until answered." (Parked
  awaiting human; do NOT redispatch — it resumes via §7.)
- **DONE-NO-CLOSE** — the work is finished but lands on a PR that does **not** close this issue
  (a _related_ issue touched by another issue's PR, or a partial contribution): "work complete;
  contributed via PR #X which does NOT close this issue. **Over and out** — orchestrator,
  reassign or close this issue as you see fit." The issue stays OPEN on purpose; the sign-out
  tells the orchestrator the worker is done so it can reassign the slot. (Not redispatchable for
  the _same_ work; the orchestrator decides the issue's disposition.)
- **ABANDONED** — "could not complete: `<reason>`. No PR / PR not viable. **Issue is free for
  pickup.**" (Explicitly redispatchable.)

**Is a closing comment necessary?** For _closure mechanics_, **no** — when the PR's body
carries a closing keyword (`Closes/Fixes/Resolves #N`), merging auto-closes the issue and
leaves a "Closed via #X" trace; a separate "closing" comment is redundant. What _does_ have
independent value is the **acceptance-point summary** posted at promotion (maps each issue
criterion to the change — for the human reviewer), and the **sign-out** (for coordination).
Keep those two; don't add a third hand-closing comment when auto-close is wired.

**Orchestrator — verify, don't assume (every loop, for each ready/merged PR):**

- Confirm the auto-close link exists:
  `gh pr view <PR> --json closingIssuesReferences --jq '[.closingIssuesReferences[]?.number]'`.
  - **Non-empty** → the issue WILL auto-close on merge; do nothing manual.
  - **Empty (PR only _references_ the issue)** → it will NOT auto-close. Either edit the PR
    body to add `Closes #N` (preferred), or on merge **manually close** the issue with a
    one-line _proposed-closure_ comment citing the merged PR. Never leave a resolved issue
    silently open — that's the state that makes a supervisor think work is still in flight.
- **Pickup rule:** an issue is redispatchable if it is OPEN **and** (no live worker owns it)
  **and** (its latest sign-out is ABANDONED, or there is a claim comment but NO sign-out and
  the worker is not live = crashed). Never redispatch an issue whose sign-out is DONE/DRAFT or
  BLOCKED. **DONE-NO-CLOSE** is not auto-redispatchable — it's a _human/orchestrator decision_
  (close as resolved-elsewhere, relabel, or re-scope into a fresh dispatch); the worker that
  signed out is done either way and its slot is freed.

---

## 8. Metrics (real wall-clock) + crash-recoverable ledger

Stamp epochs with `date +%s` (the orchestrator is the main agent — real clock allowed;
note that Workflow _scripts_ forbid `Date.now()`, this skill does not use them). Per issue
record: `dispatched_at, claimed_at, draft_at, ci_green_at, ready_at, merged_at`.

**Derived (seconds → minutes for the ledger):**

- `build_time = draft_at − dispatched_at` (worker speed)
- `ci_time = ci_green_at − draft_at` (CI duration — usually the long pole)
- `review_latency = merged_at − ready_at` (human merge wait)
- `lead_time = merged_at − dispatched_at` (end-to-end)

**Batch-level:** `throughput = merged / ((now − BATCH_START)/3600)` (PRs/hr), live `WIP`
(in-flight count), `rebase_count`, `blocked_count`. Use these to drive the dial (§5):
high `review_latency` ⇒ don't add build parallelism; high `rebase_count` ⇒ ratchet down.

**Ledger.** The crash spine is **any durable plain file outside the worktree** — there is no
plugin dependency. Use whatever the environment offers, in this order: (1) a session-memory
file if one exists (e.g. `.remember/remember.md` when that tooling is present); (2) otherwise a
plain gitignored file at the repo root such as `.resolve-open-issues-ledger.md`. The only
requirements are that it **survives a session crash** and is **not inside a worktree** (worktrees
get removed). It does not need to be committed.

Crucially, the ledger is a **convenience cache, not the source of truth** — the authoritative
state lives in the **public GitHub artifacts** (issue claims/sign-outs, open PRs, CI status). A
fresh session can rebuild the whole picture from `gh pr list`/`gh issue list` + the thread
annotations even if the ledger file is lost; the ledger just makes each wakeup cheaper. It
SHOULD hold: roles/identity, the current `max_in_flight`/`max_ready` + ratchet log, the skip
list, the conflict clusters, the ordered backlog, the per-worker STATUS table (state + the 6
epoch stamps + worker `wK`/issues/PR#/branch/cluster), blocked questions, and "next action on
resume."

---

## 9. Timers (ScheduleWakeup cadence)

- **CI_POLL** — while any PR has running checks, **adapt the interval to the observed CI
  duration**, don't hard-code it. Learn the typical run length from the `ci_time` metric (§8,
  wall-clock `ci_green_at − draft_at`) and aim to wake ~3–5 times across a run:
  - rough rule: `poll ≈ clamp(observed_ci_time / 4, 30s, 600s)`.
  - a short pipeline (~2-min unit-only run) → poll near the **30s floor** (well under 120s);
  - a long one (~20-min integration/deploy) → poll ~300–600s.
  - On the **first** PR you have no `ci_time` yet — start at ~120s, then recalibrate from the
    first measured run. If you can read an in-progress ETA (`gh run view` timing), bias toward
    "wake shortly after expected completion" rather than polling blindly.
  - Tighten when a PR is _expected_ green imminently (front of the train); relax when nothing is
    close. Respect the API budget (§4b‑1) — back off if `rate_limit` headroom drops.
- **PROMOTE/MERGE_WATCH** — folded into each wake's loop (§4 steps 4–5).
- **STUCK_RECHECK** — for BLOCKED tokens: piggyback on CI_POLL; if only blocked work
  remains, `1200s`.
- **IDLE_FALLBACK** — nothing actionable but work outstanding: `1200s–1800s`.
- **STOP** — backlog empty AND nothing in flight: don't reschedule; emit final status table.

The goal is to **catch green promptly without burning API quota or context on no-op wakes** —
measure the CI, then poll to match it, rather than holding any single fixed number.

---

## 10. Gotchas (learned, don't relearn)

- **mise PATH in git hook subprocesses:** the repo's pre-commit _local_ hooks shell out to
  the pinned `npm`; git's hook subprocess may not inherit the mise PATH, so `git commit`
  fails with "Executable `npm` not found" even though `pre-commit run` passed directly.
  Fix: export PATH **in the same shell invocation** as `git commit` (workers are told this).
- **semgrep PostToolUse hook** errors `No SEMGREP_APP_TOKEN` on every Write/Edit — it fires
  _after_ the write, so the file is still created; it's auth-missing noise, not a finding.
  Don't chase it; flag it once.
- **Worktrees branch from `origin/main`**, not the current canonical-root branch — verify
  the base HEAD when a worker reports a surprising base.
- **`needs:` doesn't imply a fork guard** — a downstream job inherits dependency ordering,
  not the upstream job's `if:`. Guard the socket-mounting job directly.
- **The repo "max open PRs per user" setting has NO API.** `settings/interaction_limits` in
  the GitHub UI can show a number, but `gh api repos/{o}/{r}/interaction-limits` returns `{}`
  and `.../rulesets` returns `[]` (verified on this repo) — native interaction-limits are only
  the `existing_users`/`contributors_only`/`collaborators_only` access gate, carrying no
  count, and admins/writers bypass them anyway. So the open-PR cap is **not machine-readable**:
  pass it in as `--max-in-flight` (§5a), never try to fetch or HTML-scrape it.

---

## 11. Repeatable prompts

- `prompts/orchestrator.md` — the top-level supervisor prompt (original instructions +
  embedded clarifications). Paste to re-run the whole batch.
- `prompts/subagent-issue.md` — the parameterized per-issue worker prompt (`{{PLACEHOLDERS}}`).
  The orchestrator fills it per issue. Includes the report-back schema + the §7 escalation.

To re-run from scratch: read this SKILL, get `--max-in-flight` (ask the human if not injected —
§5a), seed the ledger from `gh issue list --state open`, then run the merge-train loop (§4).
