# `.agents/` — agent-agnostic tooling layout

This directory is the **vendor-neutral home** for shared agent capabilities in this
repository. Tool-specific harness config (Claude Code's `.claude/`, Cursor's
`.cursor/mcp.json`, etc.) lives elsewhere; portable workflows and playbooks live
here.

Tracked in [#71](https://github.com/scottschreckengaust/e2e-ministack/issues/71).
Related: [#70](https://github.com/scottschreckengaust/e2e-ministack/issues/70)
(`AGENTS.md` first), [#72](https://github.com/scottschreckengaust/e2e-ministack/issues/72)
(MCP per-vendor paths).

## Layout (current)

```text
.agents/
├── README.md                 # this file
└── skills/                   # executable agent skills (portable)
    ├── repo-revisit/
    │   ├── SKILL.md
    │   └── prompts/
    └── resolve-open-issues/
        ├── SKILL.md
        ├── prompts/
        ├── references/
        └── scripts/
```

Planned subdirs (not yet committed — see issue #71 / [dotagents](https://github.com/bgreenwell/dotagents)):

| Subdir     | Purpose                                                                       |
| ---------- | ----------------------------------------------------------------------------- |
| `rules/`   | Invariant behavioral guidelines (optional; root `AGENTS.md` is primary today) |
| `context/` | Static reference data (read-only)                                             |
| `specs/`   | Current task requirements                                                     |

**Do not** put harness-local state here (`.claude/worktrees/`, optimizer scratch
under `*-workspace/` — those are gitignored local tooling).

## Instructions vs skills vs MCP

| Artifact                 | Location                                        | Loaded how                                                                                    | Scope                                                   |
| ------------------------ | ----------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| **Project instructions** | root [`AGENTS.md`](../AGENTS.md)                | Auto-loaded by Cursor, Claude Code, and other [agents.md](https://agents.md)-compatible tools | Always-on guidance (build, test, security, conventions) |
| **Claude harness notes** | [`CLAUDE.md`](../CLAUDE.md)                     | Auto-loaded in Claude Code; Cursor reads it for compatibility                                 | Claude-specific only (skills tool, worktree hook)       |
| **Skills**               | `.agents/skills/<name>/SKILL.md`                | Auto-discovered; model invokes when relevant or user types `/name`                            | On-demand workflows                                     |
| **MCP servers**          | Per vendor (`.mcp.json`, `.cursor/mcp.json`, …) | Tool-specific MCP config                                                                      | External tool access (GitHub API, etc.)                 |

There is **no `CURSOR.md`** convention — Cursor auto-loads `AGENTS.md`. Cursor-specific
MCP setup belongs in `.cursor/mcp.json` when present (see issue #72 / #112).

**Skills are more portable than MCP:** one `.agents/skills/` tree serves multiple
agents; MCP still needs per-vendor files or a sync generator (issue #111).

## Skills — discovery

Agents that support the [Agent Skills](https://cursor.com/docs/skills) format scan
these paths **automatically** (no import step):

| Scope                    | Path                                     |
| ------------------------ | ---------------------------------------- |
| Project (canonical here) | `.agents/skills/<skill-name>/SKILL.md`   |
| Project (Cursor alias)   | `.cursor/skills/<skill-name>/SKILL.md`   |
| Global                   | `~/.agents/skills/`, `~/.cursor/skills/` |

**Cursor** also loads legacy **Claude Code** / **Codex** skill directories when
**Settings → Features → Third-party skills** is enabled — useful during migration,
but new shared skills should land under `.agents/skills/`.

Nested `.agents/skills/` (or `.cursor/skills/`) under a monorepo subdirectory
scopes skills to files in that subtree.

## Skills — `SKILL.md` contract

Each skill is a **folder** with a required `SKILL.md`:

```text
.agents/skills/<skill-name>/
├── SKILL.md          # required — YAML frontmatter + markdown body
├── prompts/          # optional — paste-ready sub-prompts
├── references/       # optional — progressive disclosure (load on demand)
├── scripts/          # optional — helper scripts the skill invokes
└── assets/           # optional — templates, fixtures
```

**Frontmatter** (YAML at top of `SKILL.md`):

| Field                      | Required | Purpose                                             |
| -------------------------- | -------- | --------------------------------------------------- |
| `name`                     | yes      | Unique id; also the `/slash` command name           |
| `description`              | yes      | When to use — drives **automatic** invocation       |
| `paths`                    | no       | Glob patterns; limit availability to matching files |
| `disable-model-invocation` | no       | `true` = slash-only, no auto-invoke                 |

**Invocation:**

1. **Automatic (default)** — the agent reads `description` and loads the skill when
   the task matches.
2. **Manual** — user types `/` in Agent chat and picks the skill by `name`.
3. **From `AGENTS.md`** — prose pointers ("run via the `repo-revisit` skill") steer
   humans and agents without replacing auto-discovery.

Write `description` as a clear trigger phrase list (see existing skills for examples).
Keep the always-loaded body short; put situational detail in `references/` or
`prompts/` ([#110](https://github.com/scottschreckengaust/e2e-ministack/issues/110)
tracks peeling repo-specific facts out of skills → point to `AGENTS.md` instead).

## Skills shipped in this repo

| Skill                                                        | Purpose                                                                                    |
| ------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| [`repo-revisit`](skills/repo-revisit/SKILL.md)               | Documentation & governance drift audit ([`docs/REPO-REVISIT.md`](../docs/REPO-REVISIT.md)) |
| [`resolve-open-issues`](skills/resolve-open-issues/SKILL.md) | Batch GitHub issues → one PR each → merge train                                            |

## Worktrees

Isolate feature work in **`.worktrees/<branch>`** at the repo root (gitignored when
configured). From the primary checkout:

```bash
git worktree add .worktrees/<branch> -b <branch> origin/main
cd .worktrees/<branch>
```

Rebase onto `main` before opening a PR. See [`AGENTS.md`](../AGENTS.md) repository
conventions.

## Further reading

- [agents.md](https://agents.md) — portable `AGENTS.md` standard
- [Cursor Skills docs](https://cursor.com/docs/skills) — discovery paths and frontmatter
- [dotagents](https://github.com/bgreenwell/dotagents) / [dotagentsprotocol.com](https://dotagentsprotocol.com/) — broader `.agents/` layout proposals
- [`docs/MCP.md`](../docs/MCP.md) — MCP setup (Claude `.mcp.json`; per-vendor paths for Cursor et al.)
- [`docs/REPO-REVISIT.md`](../docs/REPO-REVISIT.md) — drift-audit policy (skill runner: `repo-revisit`)
