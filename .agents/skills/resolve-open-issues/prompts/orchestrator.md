# Orchestrator prompt — resolve all open issues (repeatable)

> Paste this to (re)start the supervising orchestrator for the open-issue batch. It embeds
> the original task instructions **and** the captured clarifications so a re-run reproduces
> the same behavior. The full operating model lives in `../SKILL.md`; this is the entry prompt.

---

You are resolving open GitHub issues end-to-end, **one focused PR per issue** (or one PR per
tightly-coupled bundle), looping until none remain in your assigned set: **[ISSUE_NUMBERS]**.
If no ISSUE_NUMBERS are given, resolve **all** open issues (`gh issue list --state open`).

**Read `../SKILL.md` first** — it is the operating system (state machine, CI green-gate,
concurrency dial, rebase/refill cascade, stuck/resume, metrics, timers, gotchas). This prompt
sets the goal + config; the SKILL says how to run the loop.

## Setup (once)

- **Ensure the pinned Node is on PATH** — use `node` if it's already there, else fall back to
  mise: `command -v node >/dev/null 2>&1 || export PATH="$(mise where node)/bin:$PATH"`. Confirm
  `node --version` matches the repo's pin (`mise.toml`). Do this in every shell.
- Canonical repo root = the main checkout (worktrees are created under `<root>/.claude/worktrees/`).
- Confirm identity: `gh api user --jq .login`. Issue claims + PRs authored under it. Each
  worker's public traceable identity is `@<gh-login> (agent:wK)` — `wK` is a sequential handle
  YOU assign at dispatch (`w1`, `w2`, …), not an issue number, since one worker may cover
  several folded issues. The greppable resume token is `agent:wK`. The worker names the
  issue(s) it covers in its claim.

## Launch parameter: `--max-in-flight N` (injected; the open-PR ceiling)

- **`N` is the hard ceiling on open PRs.** It is **injected at launch**, NOT discovered: the
  repo's `settings/interaction_limits` "max open PRs per user" is a GitHub UI-only control with
  **no API** (`gh api repos/{o}/{r}/interaction-limits` → `{}`, `.../rulesets` → `[]`). Do NOT
  fetch or HTML-scrape it. (SKILL §5a / §10.)
- **If the launch prompt did NOT pass `--max-in-flight`, ASK me before dispatching**, offering
  the default **`3`** as the starting point.
- **Range `1..1000`** (1000 = the UI's own max; there is no smaller built-in limit).
- **Adaptive ratchet:** start `max_in_flight` at `N` (default 3). Each clean loop (CI green
  first-try AND `gh api rate_limit` core-remaining >1000) ratchet **up by 1** toward the
  ceiling; on any rate-limit signal (§4b) ratchet **down by 1** (floor 1) + widen CI-poll.
  `max_ready` starts at 1 and may grow (cap ~3) only when merges are smooth and clusters
  disjoint (SKILL §5a). Log every change (`knob: old→new` + trigger) in the ledger.

## Pilot mode (optional on-ramp; default for a fresh repo)

**Steady-state** = the §4 loop with the adaptive ratchet live. **Pilot mode** only differs by
**holding the ratchet flat** until the first PR goes fully BACKLOG→MERGED — so repo/CI surprises
surface at low width. Once one PR merges clean, release the ratchet → steady-state. Skip pilot
mode on a repo you've run before; set `N=1` for a strict single-issue dry run. (SKILL §5b.)

## Authoritative config

- **Pipeline caps:** `max_ready` starts at 1 (merge-train front) + draft funnel
  `max_draft = max_in_flight − ready_count` (live ready count, not the cap — SKILL §2/§3);
  total open PRs ≤ the injected `--max-in-flight` (default 3,
  ceiling 1000). Both caps adapt (SKILL §5a). (Dial: SKILL §5.)
- **Worker contract:** each issue gets ONE background worker (`prompts/subagent-issue.md`) that
  goes root-cause → worktree → TDD → local gates → **draft PR** → report, then **STOPS**.
  Workers never mark ready, never poll CI in a loop, never close issues, never touch
  out-of-scope files, never remove their worktree.
- **Dispatch by FILLING the template — never paraphrase it.** Read
  `prompts/subagent-issue.md` and substitute its literal `{{PLACEHOLDERS}}`; dispatch **that**
  text. Do **NOT** reconstruct/summarize the worker prompt from memory — **re-read the file
  every batch** so steps merged since you last looked (e.g. the §Step 0a self-assign) propagate
  automatically. (A from-memory paraphrase silently drops the newest step — exactly how a batch
  once ran without self-assigning; see SKILL §10.) **Pre-dispatch checklist (per worker):**
  template re-read this batch? · `{{PLACEHOLDERS}}` all filled (`ISSUES`, `N`, `SLUG`,
  `ALLOWED_FILES`, `COMMIT_*`, `COAUTHOR_TRAILER`)? · Step 0a self-assign present? ·
  scope/allowed-files set?
- **Promotion is orchestrator-only and green-gated:** promote draft→ready **only** when CI is
  all-green AND `ready_count < max_ready` AND no other PR from the same hot cluster is already
  ready. Put a timer on CI (don't promote on elapsed time). On CI-red, wake the worker to fix.
- **Conflict policy:** parallel-with-rebase-at-merge; **serialize the _ready_ state within hot
  clusters** (workflows; stack+snapshot) so only one of each is ready at a time. On each merge,
  rebase the next same-cluster PR onto main, re-green, then promote.
- **Folding (decided in Phase 0 triage, SKILL §4):** combine tightly-coupled issues into one
  worker/PR when they share a concern and a reviewer can take them in one scope — encouraged, it
  cuts review/rebase overhead. Annotate every folded issue + note it for the supervisor. Else
  one-PR-per-issue.
- **Sequencing for the human:** on each promotion post a "🔀 Merge guidance (for the reviewer)"
  comment **on the PR** (independent vs must-follow-#X, cluster, merge order), mirrored to the
  issue. Merge order is driven by clusters, NOT PR-number recency — say so.
- **Stuck protocol:** a blocked worker pushes its branch + opens a **draft `[BLOCKED]` PR**
  (`Relates to`, never `Closes`) documenting the decision/options + a "how to take over" note,
  posts numbered questions on the issue+PR under `@<login> (agent:wK)`, and stops. A human (or
  any other agent/automation) answers by addressing the `agent:wK` token or by picking up the
  pushed branch; the orchestrator detects the reply and warm/cold-resumes (SKILL §7). The draft
  PR is the durable hand-off artifact — don't mistake a `[BLOCKED]` draft for a stray/abandoned PR.
  **A license/governance-policy conflict is a first-class block** (the worker prompt's "Adopting a
  NEW tool" gate): the reply you're waiting for is a _decision_ (use alternative X / drop the issue
  / override with reason), not a clarification — resume the worker with it the same way.
- **Durability:** maintain the crash-recoverable ledger every loop (any durable file outside a
  worktree — a session-memory file if present, else a gitignored `.resolve-open-issues-ledger.md`
  at the repo root; SKILL §8). It's a cache — the public issue/PR threads are the real source of
  truth. Record per-worker epoch stamps + states + worker `wK`/agentIds. Refine the SKILL during the run.

## Per-issue workflow (delegated to each worker; you supervise)

0. **Claim** — worker comments on each issue it covers: `@<login> (agent:wK) working on it — issues #N[, #M …] — branch fix/issue-N-<slug>` (branch named for the primary/lowest issue).
1. **Root cause first** — reproduce empirically (run code, don't theorize). Search adjacent open
   issues; fold or annotate shared-file/shared-cause dependencies.
2. **Isolate** — `git worktree add -b fix/issue-N-<slug> .claude/worktrees/fix-issue-N-<slug> origin/main`; `npm ci`; push the branch to signal state.
3. **TDD** — failing test that reproduces (fails for the RIGHT reason) → minimal fix → green.
4. **Local gates (all green before PR):** run the repo's **own** declared gates — `pre-commit
run` plus the relevant `package.json`/CI scripts — don't hard-code a list (it goes stale).
   **Never regress a gate below its current high-water mark** (e.g. the mutation tier is at
   **100%** today — keep it there, even though CI's floor is lower). If the synthesized template
   changed: update the snapshot (`-u`) **deliberately** and inspect the diff. (Details: worker prompt.)
5. **Commit** (append the co-author trailer you inject as `{{COAUTHOR_TRAILER}}` — e.g.
   `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`; set it once here so the model name
   never rots in two files) + push.
6. **Draft PR** (`gh pr create --draft`) with: Summary (`closes #N`), reproduced root cause +
   evidence, the fix + why it's best-practice, Testing (commands + results), Dependencies/related
   (cross-link issues/PRs touching the same area). Worker then STOPS and reports.

## Orchestrator loop (you; every wakeup) — see SKILL §4

**First, once:** run **Phase 0 triage** (SKILL §4) — list issues, assign clusters by shared
files, decide folds, write the ordered backlog + cluster map to the ledger. Then each wakeup:

Reconcile (gh pr list + ledger) → collect worker reports → poll `gh pr checks` → promote
green drafts (slot+cluster gated) with merge-guidance annotation → on merge close the issue with
an acceptance-point summary + run rebase/refill cascade → handle escalations → refill to caps →
update metrics + ledger → `ScheduleWakeup` (CI_POLL adapted to observed CI duration — SKILL §9; 1200–1800s idle) or
STOP when backlog empty AND nothing in flight (emit final per-PR status table).

## Rate limits (SKILL §4b)

Expect two kinds on a long batch: (1) your own `gh`/API limit — check `gh api rate_limit`,
remedy is to **slow polling** and wait for reset; (2) Actions-side limits that surface as **job
failures** (registry-pull throttle, 429 from a step, concurrency caps). For a red check, ALWAYS
inspect the log first (`gh run view <id> --log-failed`) and classify: **transient** (rate-limit /
network) → `gh run rerun <id> --failed` _after_ confirming you're not still being limited (bound
to ≤2 retries, log `rerun_count`); **real** (test/lint/scan finding) → wake the subagent to fix.
Never blind-retry. During a throttle, ratchet `max_in_flight` down (SKILL §5a).

## Resource sizing

Start `max_in_flight` at the injected `N` (default 3) and watch the first wave's local-gate
timings + `gh api rate_limit`; apply the adaptive ratchet (SKILL §5a) — up while the box stays
comfortable and CI is clean, down on rate-limits or piling rebases/CI-failures.

## Closure & sign-out (SKILL §7b — avoid stranding / double-dispatch)

- **Don't hand-close when auto-close is wired.** Verify each ready/merged PR actually links its
  issue: `gh pr view <PR> --json closingIssuesReferences`. Non-empty → merging auto-closes it
  (a separate "closing" comment is redundant — keep only the acceptance-point summary + the
  worker's sign-out). **Empty (PR merely references #N) → it will NOT auto-close**: add
  `Closes #N` to the PR body, or manually close on merge with a one-line proposed-closure comment.
- **Sign-out disambiguates exit.** Each worker's final public act (on every issue it covers) is
  `🤖 @<login> (agent:wK) — signing out, over and out.` + terminal state (DONE/DRAFT, BLOCKED,
  DONE-NO-CLOSE, or ABANDONED→free for pickup). **Pickup rule:** redispatch an issue if OPEN + no
  live worker + (sign-out=ABANDONED, or a claim comment with NO sign-out and worker not live =
  crashed). Never redispatch DONE/DRAFT or BLOCKED.

## Never

Never mark a PR ready while any check is red or pending. Never let a worker edit outside its
issue scope. Report blockers immediately. When the set is empty, report one line per PR
(number, URL, state, CI result) and stop.
