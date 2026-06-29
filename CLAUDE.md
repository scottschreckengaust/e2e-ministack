# CLAUDE.md

**[AGENTS.md](./AGENTS.md)** is the single source of truth for this repo (project, build, test, security, pinning) — for any coding agent and for humans. It is imported in full below so it loads into context every session; do not duplicate its content here.

@AGENTS.md

## Claude-specific

Only things that are NOT true for other agents belong here (everything portable lives in AGENTS.md):

- When the user types `/<skill>`, invoke it via the **Skill tool** (Claude Code's skill mechanism) — see the available-skills list in context, and never invent a skill name that isn't listed.
- **Worktrees:** use the repo's canonical `.worktrees/<branch>` path (see AGENTS.md), not Claude's native default of `.claude/worktrees/`. The native base path isn't settings-configurable, so just create worktrees with plain git — `git worktree add .worktrees/<branch> -b <branch>`, then `cd` in and launch `claude` — rather than the native `--worktree`/`EnterWorktree` flow.
