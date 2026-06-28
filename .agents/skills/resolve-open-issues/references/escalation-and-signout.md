# Escalation, sign-out, pickup & auto-close verification

Load this when a worker blocks, or at a closure / pickup decision. The worker-side mechanics live
in `prompts/subagent-issue.md`; this file is the orchestrator's half plus the shared rules.

## Stuck → escalate → resume

A worker escalates when it hits an ambiguity it cannot resolve within its issue's scope (a design
choice, conflicting acceptance criteria, a missing decision, an unexpected blocker — **or a
license/governance-policy conflict**, e.g. the issue asks for a tool the project's policy forbids;
see the worker prompt's "Adopting a NEW tool" gate).

A **governance-policy block is a first-class BLOCKED cause**, but its resume "answer" is a
_decision_, not a clarification: the worker has already posted the conflict + a compliant
alternative, so the human's reply is typically "use alternative X" / "drop this issue" / "override
the policy here, with reason." Resume the worker with that decision exactly as a clarification.

**Worker side** (durable hand-off, then stop): push the branch and open a draft `[BLOCKED]` PR
(`Relates to #N`, NEVER `Closes`) so the work is pickup-ready by **anyone**, not just resumable by
the one worker. The PR body carries the numbered questions + options/tradeoffs/recommended-default,
what was tried, the partial state, and a "how to take over" line. Post the same questions on the
issue AND the PR under `@<login> (agent:wK)`, report `STATE: BLOCKED`, and STOP. (Full worker steps:
`prompts/subagent-issue.md` § If BLOCKED.)

**Orchestrator side** (park + free slot): mark the issue BLOCKED in the ledger and record the
questions plus the worker's branch/worktree/PR. BLOCKED **frees the build slot** (don't count it) →
refill from backlog.

**Human side** (the resume signal): the human replies in the issue **or** PR thread **addressing the
agent identity** — a comment containing the worker's `agent:wK` token. Addressing `agent:wK` _is_ the
resume signal, **because** that token is greppable and survives a crash even when the in-session
agentId is lost.

**Orchestrator side** (detect + resume): the STUCK_RECHECK scan finds a reply addressing `agent:wK`,
then resumes — **warm** (SendMessage the answer to a live agentId + "continue to draft from your
existing branch/PR") or **cold** (a fresh worker + the Q&A + "branch/worktree/PR `<exact branch>`
already exist — resume, do not recreate"; read the exact branch from the PR/claim comment, never
guess a `fix/issue-N` pattern — see `ci-and-rate-limits.md`). The resumed worker finishes to draft;
the token re-enters at DRAFT.

## Terminal sign-out (the worker's FINAL public act)

"Issue OPEN + a `working on it` claim comment" is ambiguous — actively-working / parked-at-draft /
blocked / **crashed mid-task** all look identical, so a supervisor either skips a pickable issue or
double-dispatches a live one. The fix is an unambiguous sign-out, posted on every issue the worker
covers: `🤖 @<login> (agent:wK) — signing out, over and out.` + exactly one terminal state:

- **DONE/DRAFT** — draft PR opened, body uses `Closes #N` (auto-closes on merge); now in the
  orchestrator's review pipeline. (Parked; do NOT redispatch.)
- **BLOCKED** — blocked on the posted questions; draft `[BLOCKED]` PR opened (branch pushed, open for
  pickup); not working until answered. (Parked; resume via the protocol above.)
- **DONE-NO-CLOSE** — work finished but landed on a PR that does **not** close this issue (a
  _related_ issue, or a partial contribution): the issue stays OPEN on purpose; "orchestrator,
  reassign or close as you see fit." (Not auto-redispatchable — a human/orchestrator decision.)
- **ABANDONED** — **first un-assign** (`gh issue edit <N> --remove-assignee @me` for every issue
  covered) so the board shows it pickable, then the reason. (Explicitly redispatchable.) DONE /
  DRAFT / DONE-NO-CLOSE keep the assignee — merge auto-close clears it on resolved ones.

**No separate hand-closing comment** when `Closes #N` is wired — merging auto-closes and leaves a
"Closed via #X" trace, so a third comment is redundant. Keep only the two that carry independent
value: the **acceptance-point summary** (posted at promotion, maps each issue criterion to the
change — for the reviewer) and the **sign-out** (for coordination).

## Auto-close verification (verify, don't assume — every loop, each ready/merged PR)

Reconcile the auto-close links against **every** issue the worker reported in `ISSUES:`, not merely
that the list is non-empty:

```bash
gh pr view <PR> --json closingIssuesReferences --jq '[.closingIssuesReferences[]?.number]'
```

Compare that set against `ISSUES:` **and** the worker's per-issue intent:

- **Each issue is auto-closing OR explicitly DONE-NO-CLOSE** → correct; do nothing manual.
- **A fully-resolved issue is missing its `Closes` link** (a real strand — e.g. folded #11+#20 both
  done but the body only lists `Closes #11`) → fix it: edit the PR body to add `Closes #N`
  (preferred), or on merge manually close with a one-line proposed-closure comment citing the PR.
  Never leave a _resolved_ issue silently open — that's the exact state that makes a supervisor think
  work is still in flight. (Note: a backticked `` `Closes #N` `` does NOT auto-close — the keyword
  must be unformatted.)

## Pickup rule + the cold-resume hazard

An issue is **redispatchable** iff it is OPEN **and** no live worker owns it **and** (its latest
sign-out is ABANDONED, OR there is a claim comment but NO sign-out and the worker is not live =
crashed). Never redispatch DONE/DRAFT or BLOCKED. DONE-NO-CLOSE is a human/orchestrator decision, not
auto-redispatch.

**⚠️ Cold-resume hazard:** "claim, no sign-out" is ambiguous between crashed and currently-running.
On a fresh/cold orchestrator the agentId liveness map is gone, so every in-progress worker also looks
"not live." Do **not** treat that as crashed and redispatch — that double-dispatches live workers.
Instead **probe the public artifacts first**: if a branch (`git ls-remote --heads origin
'fix/issue-N-*'`) or a draft PR exists, assume work is in flight and adopt it (cold-resume). Only
treat it as crashed when **no branch and no PR** exist after a grace re-poll (one CI_POLL cycle).
When in doubt, re-poll before redispatching.
