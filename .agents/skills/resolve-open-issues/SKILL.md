---
name: resolve-open-issues
description: Use this skill to fix a whole batch of GitHub issues automatically, each landing as its own merged PR, while the user steps away. Reach for it whenever the request is about issues in bulk rather than one specific bug — e.g. "fix all my open issues," "clear / burn down / knock out / work the backlog," "go through every issue, one PR each," "resolve #3 #4 #9," "spin up agents on my issues overnight," "draft → green → merge → next until empty," or naming a repo to grind through. The common thread: many issues plus a hands-off, end-to-end loop (fix → open PR → pass CI → merge → take the next), often unattended, with several PRs in flight. Don't use it for one item: fixing one named bug, opening/reviewing/merging one PR, rebasing one branch, or diagnosing why CI is red.
---

# Resolve Open Issues — batch PR pipeline

A supervising **orchestrator** drives many GitHub issues to merge, **one focused PR per
issue** (or one PR per tightly-coupled bundle), by dispatching one **worker subagent** per
issue and metering them through a bounded draft→ready→merged pipeline.

The operating model is a **merge-train**: build many PRs in parallel as drafts, keep a small
"Ready for Review" front (start at one) rebased onto latest `main` and all-green, merge it,
advance, promote the next. This file is the always-loaded core — roles, config, the state
machine, the loop, the ledger. Situational detail lives in `references/` (loaded only when
its situation arises) and the two paste-ready prompts live in `prompts/`.

To re-run from scratch: read this file, get `--max-in-flight` (ask the human if not injected —
see `references/concurrency-and-merge.md`), seed the ledger from `gh issue list --state open`,
then run the loop (§4).

> **Portable vs repo-specific.** The pipeline itself is **repository-agnostic** — the roles, the
> state machine, the green-gate (local checks pass → push **draft** → wait for **all-green CI** →
> flip **ready** → merge), the concurrency dial, escalation, sign-out, and the metrics work on any
> repo with GitHub + CI. What is **per-repo** is only the substituted detail: which gates run and
> their thresholds (read from the repo's own config, never hard-coded — §7), the governance policy
> the worker enforces (this repo's AGPL/copyleft stance is one instance — see
> `prompts/subagent-issue.md`), and the harness quirks in `references/gotchas.md`. Carry the core to
> a new repo unchanged; re-derive those few specifics from the new repo's config and docs.

---

## 1. Roles (never blur these)

- **Orchestrator** (you, the main agent): owns the pipeline. Dispatches workers, polls CI,
  promotes draft→ready, rebases, merges/closes, refills, keeps the ledger + metrics, handles
  escalations, stays in the loop across wakeups. Does NOT write issue fixes itself.
- **Worker subagent** (one per unit of work, `run_in_background: true`): root-cause → worktree →
  TDD → local gates → commit/push → **DRAFT PR** → sign-out → **STOP**. A worker NEVER marks
  ready, NEVER polls CI in a loop, NEVER closes issues, NEVER touches files outside its scope,
  NEVER removes its worktree. If blocked, it escalates and stops.

This split exists **because only one actor (the orchestrator) ever counts slots** — so there is
no race on "how many PRs are ready."

---

## 2. Authoritative config (the operating defaults)

The dial (`references/concurrency-and-merge.md`) changes these deliberately; absent a reason,
use them.

- **Caps:** `max_ready` starts at **1** (the train front). `max_in_flight` is **injected at
  launch** (`--max-in-flight`, default **3**, ceiling **1000**) and is the single global ceiling
  on open PRs. The dispatch funnel is `max_draft = max_in_flight − ready_count`, computed from the
  **live** ready count (not the `max_ready` cap) **because** that keeps an empty ready slot usable
  by a draft, so raising `max_ready` adds throughput instead of starving the build funnel. Both
  caps adapt via the ratchet (`references/concurrency-and-merge.md`).
- **Worker contract:** stop at draft PR + report (§1). The orchestrator promotes.
- **Conflict policy:** _parallel-with-rebase-at-merge_. Open PRs in parallel; **serialize the
  _ready_ state within a hot cluster** (only one PR from a shared-file cluster is ready at a time)
  **because** that cuts rebase thrash without serializing the build stage.
- **Folding:** combine tightly-coupled issues into one worker/PR when they share a concern and a
  reviewer can take them in one scope (decided in Phase 0, §4) — encouraged **because** it cuts
  review and rebase overhead. **Never fold across clusters** so each PR carries exactly one cluster
  tag and the one-ready-per-cluster rule stays well-defined. Annotate every folded issue.
- **Identity:** issue claims + PR authorship under the `gh` login (`gh api user --jq .login`). Each
  worker's public identity is **`@<gh-login> (agent:wK)`**, where `wK` is a sequential handle the
  orchestrator hands out at dispatch (`w1`, `w2`, …), NOT an issue number, **because** one worker
  may cover several folded issues. `agent:wK` is the greppable resume token. The worker also
  **self-assigns the GitHub assignee** as its first claim action — the native ownership signal
  (Assignees column + `assignee:<login>` filter) that complements the comment.
- **Durability:** keep a crash-recoverable ledger (§5). Refine this skill during the run.

---

## 3. Pipeline state machine

Each issue is a token the orchestrator advances each loop.

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
- **BUILDING** — a worker is active (counts against `max_draft`).
- **DRAFT** — PR open, worker reported & stopped; CI running (still a draft slot).
- **BLOCKED** — worker escalated; **parked, frees its slot**, awaits a human answer.
- **READY** — CI green + promoted by the orchestrator (counts against `max_ready`).
- **MERGED** — merged; frees a ready slot, advances `main`, triggers the rebase+refill cascade,
  then the issue closes.

Slot accounting: `in_flight ≤ max_in_flight` is the global ceiling; `ready ≤ max_ready` gates
promotion; new dispatches need `building + draft ≤ max_draft`. BLOCKED counts toward none.

---

## 4. The orchestrator loop

**Phase 0 — Triage & cluster (ONCE at startup; refresh when the backlog changes).** This is where
folds and clusters are decided, before any dispatch:

1. List the work: `gh issue list --state open` (or the injected `[ISSUE_NUMBERS]`).
2. For each issue, note the files/area it will most likely touch (from its text + a quick look at
   the cited code). Group issues touching the **same file(s)/subsystem** into a named **cluster**.
   Different clusters merge in any order; same-cluster issues serialize at ready/merge (§6).
3. **Fold** only tightly-coupled, same-cluster issues a reviewer would take together (§2). When
   unsure, keep them separate.
4. Write the **ordered backlog + cluster map + fold decisions** to the ledger (§5) so a crash can
   rebuild them. This is the "cluster-priority order" steps 4 and 7 refer to.

**The loop (every wakeup):**

1. **Reconcile** — `gh pr list --state open` + read ledger; reconstruct each token's state (cheap,
   idempotent — survives crashes). Stamp `now=$(date +%s)`.
2. **Collect worker reports** — for each finished background worker, record
   PR#/branch/worktree/gates/`draft_at`; mark DRAFT (or BLOCKED if it escalated).
3. **Poll CI** — for each DRAFT/READY PR, `gh pr checks <pr>`. On newly all-green, stamp
   `ci_green_at`. On red, classify then act — see `references/ci-and-rate-limits.md`. Don't promote
   a non-green PR.
4. **Promote** (draft→ready) — for each green DRAFT, **in cluster-priority order**, if
   `ready_count < max_ready` AND no other PR from its hot cluster is already READY: `gh pr ready
<url>`, stamp `ready_at`, post the merge-guidance annotation (§6), increment `ready_count`.
5. **Merge watch** — get READY PRs merged (native auto-merge or direct, per
   `references/concurrency-and-merge.md`), stamp `merged_at`, close/reconcile the issue(s) with an
   acceptance-point summary (verify auto-close per `references/escalation-and-signout.md` §
   Auto-close verification), free the slot, then run the rebase+refill cascade (§6).
6. **Escalations** — for BLOCKED tokens, scan the issue/PR thread for a human reply addressing
   `agent:wK`; if found, resume — see `references/escalation-and-signout.md`.
7. **Refill** — while `building + draft < max_draft` and the backlog is non-empty, pick the next
   issue (cluster-spread; hot clusters one at a time) and dispatch a worker (§7).
8. **Metrics + ledger** — recompute and write the ledger (§5).
9. **Reschedule** — `ScheduleWakeup` for the next wake (cadence in
   `references/ci-and-rate-limits.md`), or STOP if the backlog is empty AND nothing is in flight
   (then emit the final per-PR status table).

**The green-gate is baked in:** a PR is **never** promoted on elapsed time — only on all-green CI
while a ready slot is free. Background subagents **cannot self-schedule**, so the orchestrator owns
every wakeup and the subagent only performs fixes. Full CI classification, warm/cold resume, and
rate-limit handling: `references/ci-and-rate-limits.md`.

---

## 5. Ledger + metrics (written every loop)

Keep a crash-recoverable **ledger**: any durable plain file **outside** the worktree (worktrees get
removed) — a session-memory file if one exists (e.g. `.remember/remember.md`), else a gitignored
`.resolve-open-issues-ledger.md` at the repo root. It needn't be committed.

The ledger is a **convenience cache, not the source of truth** — the authoritative state lives in
the **public GitHub artifacts** (issue claims/sign-outs, open PRs, CI status), **because** a fresh
session must be able to rebuild the whole picture from `gh pr list` / `gh issue list` + thread
annotations even if the ledger is lost. It SHOULD hold: roles/identity, the current
`max_in_flight`/`max_ready` + ratchet log, the skip list, the clusters, the ordered backlog, the
per-worker STATUS table (state + the six epoch stamps + `wK`/issues/PR#/branch/cluster), blocked
questions, and "next action on resume."

Stamp epochs with `date +%s` (the orchestrator is the main agent — the real clock is allowed).
Per issue record `dispatched_at, claimed_at, draft_at, ci_green_at, ready_at, merged_at`; the
derived times and how they drive the dial are in `references/concurrency-and-merge.md`.

---

## 6. Sequencing, rebase & refill cascade

Hot-cluster PRs (same file) merge cleanly only one at a time. On every merge:

1. **Identify the next same-cluster PR** (ledger cluster tag, cluster-priority order).
2. **Rebase it onto the new `main`:** in its worktree, `git fetch origin && git rebase
origin/main`; resolve minimally or warm-resume the worker; push `--force-with-lease`.
3. **Re-run local gates** (cheap unit tier). If green, it's promotion-eligible.
4. **Refill:** the merge freed a ready slot and usually a build slot — dispatch the next backlog
   issue to keep `building + draft` at the cap.

**Merge-guidance annotation — post on the PR, mirror to the issue.** When a PR is promoted, post a
**"🔀 Merge guidance (for the reviewer)"** comment **on the PR** (the human reviews there, so the
order must live there) stating: whether it's independent or **must-follow #X** (rebase after that
merges); its cluster + position + the PRs queued behind it; and a one-line action. Say so
explicitly **because** merge order is driven by file-conflict clusters, NOT PR-number recency.
Different-cluster PRs have no ordering constraint; same-cluster PRs merge in sequence.

---

## 7. Dispatching workers

Each issue (or fold) gets ONE background worker built from `prompts/subagent-issue.md`.

**Dispatch by FILLING the template — never paraphrase it.** Read `prompts/subagent-issue.md` and
substitute its literal `{{PLACEHOLDERS}}`; dispatch _that_ text. Re-read the file **every batch**,
**because** a from-memory paraphrase silently drops whatever step was merged since the last look
(a real batch once ran without self-assigning for exactly this reason — see
`references/gotchas.md`). Per-worker pre-dispatch checklist: template re-read this batch? ·
`{{PLACEHOLDERS}}` all filled (`ISSUES`, `N`, `SLUG`, `ALLOWED_FILES`, `COMMIT_*`,
`COAUTHOR_TRAILER`)? · self-assign step present? · scope/allowed-files set?

Workers escalate, sign out, and hand off per `references/escalation-and-signout.md`; the
orchestrator parks BLOCKED tokens (freeing the slot) and resumes them when a human addresses
`agent:wK`.

---

## Reference files (load on the matching situation)

- **`references/concurrency-and-merge.md`** — the merge-train model, the concurrency dial, the
  adaptive ratchet, pilot mode, the merge-closer (who merges, branch-protection/self-approval), and
  the derived metrics that drive the dial. Load when tuning width or merging.
- **`references/ci-and-rate-limits.md`** — CI green-gate classification, warm/cold subagent resume,
  the two rate-limit classes (inspect → classify → re-run, never blind-retry), and the
  `ScheduleWakeup` cadence. Load when a check is pending/red or on a rate limit.
- **`references/escalation-and-signout.md`** — the stuck→escalate→resume protocol, terminal
  sign-out, the pickup rule, auto-close verification, and the cold-resume double-dispatch hazard.
  Load when a worker blocks or at closure/pickup decisions.
- **`references/gotchas.md`** — repo/harness quirks that read as real failures but aren't (mise
  PATH, semgrep hook, worktree base, the no-API PR cap, paraphrase drift). Skim before the first
  dispatch.

## Prompts

- **`prompts/orchestrator.md`** — the top-level supervisor prompt (original task + clarifications).
  Paste to re-run the whole batch.
- **`prompts/subagent-issue.md`** — the parameterized per-issue worker prompt. The orchestrator
  fills its `{{PLACEHOLDERS}}` and dispatches it; it carries the report-back schema + escalation.
