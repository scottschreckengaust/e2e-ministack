# Orchestrator prompt — resolve all open issues (repeatable)

> Paste this to (re)start the supervising orchestrator. It sets the **goal + launch config**; the
> full operating model (state machine, green-gate, dial, cascade, escalation, metrics, timers,
> gotchas) lives in `../SKILL.md` and its `references/`. This prompt deliberately does NOT restate
> the loop — read the SKILL for that, **because** a paraphrase here would drift from the SKILL as it
> evolves.

---

You are resolving open GitHub issues end-to-end, **one focused PR per issue** (or one PR per
tightly-coupled bundle), looping until none remain in your assigned set: **[ISSUE_NUMBERS]**. If no
ISSUE_NUMBERS are given, resolve **all** open issues (`gh issue list --state open`).

**Read `../SKILL.md` first** — it is the operating system. This prompt only supplies what the SKILL
leaves to launch: the goal above, the launch parameter below, and the setup facts.

## Setup (once)

- **Ensure the pinned Node is on PATH** in every shell: `command -v node >/dev/null 2>&1 || export
PATH="$(mise where node)/bin:$PATH"`; confirm `node --version` matches `mise.toml`.
- Canonical repo root = the main checkout (worktrees go under `<root>/.claude/worktrees/`).
- Confirm identity: `gh api user --jq .login`. Issue claims + PRs author under it; each worker signs
  as `@<gh-login> (agent:wK)` (SKILL.md §2).

## Launch parameter: `--max-in-flight N` (the open-PR ceiling)

`N` is the hard ceiling on open PRs, **injected at launch, not discovered** (the repo's per-user PR
cap has no API — `references/gotchas.md`). **If the launch prompt did NOT pass `--max-in-flight`,
ASK before dispatching** (offer the default **3**; range `1..1000`). The adaptive ratchet and pilot
mode are in `references/concurrency-and-merge.md`.

## Run the loop

1. **Phase 0 triage, once** (SKILL.md §4): list issues, assign clusters by shared files, decide
   folds, write the ordered backlog + cluster map to the ledger.
2. **Each wakeup**, run the §4 loop: reconcile → collect reports → poll CI → promote (slot+cluster
   gated, with merge-guidance) → merge + close (verify auto-close) + rebase/refill cascade → handle
   escalations → refill to caps → update metrics + ledger → `ScheduleWakeup` or STOP.
3. **Dispatch by FILLING `prompts/subagent-issue.md`** — re-read it every batch and substitute its
   `{{PLACEHOLDERS}}`; never paraphrase it (SKILL.md §7, `references/gotchas.md`).

## Guardrails (the SKILL has the detail; these are the non-negotiables)

- **Promotion is orchestrator-only and green-gated** — never on elapsed time, never while any check
  is red/pending, never two ready from one hot cluster (SKILL.md §4, `references/ci-and-rate-limits.md`).
- **Workers never** mark ready, poll CI in a loop, close issues, edit out-of-scope files, or remove
  their worktree. A blocked worker leaves a pushed branch + draft `[BLOCKED]` PR and posts questions
  under `agent:wK`; you park it (freeing the slot) and resume on a reply addressing that token
  (`references/escalation-and-signout.md`). A **license/governance conflict is a first-class block**
  whose resume answer is a _decision_.
- **Don't hand-close when auto-close is wired** — verify `closingIssuesReferences` per issue; keep
  only the acceptance-point summary + the worker's sign-out (`references/escalation-and-signout.md`).
- **Rate limits:** inspect → classify → re-run; never blind-retry (`references/ci-and-rate-limits.md`).
- **Durability:** maintain the crash-recoverable ledger every loop; it's a cache — the public
  issue/PR threads are the source of truth (SKILL.md §5). Refine the SKILL during the run.

When the set is empty AND nothing is in flight, emit one line per PR (number, URL, state, CI result)
and stop.
