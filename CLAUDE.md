# CLAUDE.md

## General instructions

Read **[AGENTS.md](./AGENTS.md)** — it is the single source of truth for this repo (project, build, test, security, and pinning knowledge). Everything that applies to any coding agent lives there; do not duplicate it here.

## Claude-specific

Only things that are NOT true for other agents belong here:

- When the user types `/<skill>`, invoke it via the **Skill tool** (Claude Code's skill mechanism) — see the available-skills list in context, and never invent a skill name that isn't listed.
- `.claude/` holds Claude Code's local configuration (settings, skills, worktrees). It is tooling, not project code — ignore it when reasoning about the application (the same way `.remember/` is ignored per AGENTS.md).
