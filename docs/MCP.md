# MCP servers

This repo ships a repo-wide [Model Context Protocol](https://modelcontextprotocol.io)
configuration in [`.mcp.json`](../.mcp.json) (the Claude Code / CLI location) so an
agent can interact with the project and the GitHub repository.

> **Scope.** `.mcp.json` is the **Claude Code** project-scope file. Other agents
> read their own paths (`.vscode/mcp.json`, `.cursor/mcp.json`, Codex
> `config.toml`, …) — see [Other editor/agent vendors](#other-editoragent-vendors).

## Servers

| Server               | Transport                  | Purpose                                         |
| -------------------- | -------------------------- | ----------------------------------------------- |
| `threat-composer-ai` | `uvx` (AWS, pinned commit) | Threat-model authoring (see THREAT-MODELING.md) |
| `github`             | remote HTTP                | Read/write the GitHub repo (issues, PRs, etc.)  |

## GitHub MCP server — setup (remote HTTP, default)

The `github` server connects to GitHub's **remote** MCP endpoint
(`https://api.githubcopilot.com/mcp/`) over streamable HTTP, authenticated by a
personal access token passed in the `Authorization` header. Claude Code expands
`${GITHUB_PERSONAL_ACCESS_TOKEN}` in `.mcp.json` from its **launch environment**,
so the committed config carries no secret. Supply the token from any **per-developer,
gitignored** location Claude Code reads into the launch environment (pick one — never
a committed file):

```bash
# (a) ~/.claude/settings.json — Claude global, applies to every project:
#       { "env": { "GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_..." } }

# (b) .claude/settings.local.json — Claude project-local override (this repo
#     only); gitignored. Same { "env": { ... } } shape as (a).

# (c) the shell you launch `claude` from (Claude does NOT auto-read .env):
cp .env.example .env   # then edit GITHUB_PERSONAL_ACCESS_TOKEN
set -a; . ./.env; set +a
claude
```

Other agents use their own loader (Cursor/VS Code env, a `.env`, the shell). Scope
the token to the minimum you need (`repo` + `read:org` is typical). `.env`,
`.claude/settings.local.json`, and `~/.claude/settings.json` are never committed —
see `.gitignore`. The token reaches the server only via the `Authorization: Bearer …`
header that `.mcp.json` builds from the env var; if the var is unset the entry falls
back to an empty token (`${…:-}`) so the server merely fails to authenticate rather
than breaking config parsing.

### Headers `.mcp.json` sends to the `github` server

GitHub's remote server takes the `Authorization` header (the only secret) plus five
optional `X-MCP-*` toggles ([authoritative list](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md#optional-headers)).
This PoC sets four; all are passed through verbatim by Claude Code:

| Header           | Value (PoC) | Effect                                                                                                                                      |
| ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Authorization`  | from env    | `Bearer <PAT>` — the only secret; supplied via `${GITHUB_PERSONAL_ACCESS_TOKEN}` (see above).                                               |
| `X-MCP-Toolsets` | `all`       | Toolset groups to expose. Narrow it (e.g. `repos,issues,pull_requests`) to shrink the surface area.                                         |
| `X-MCP-Readonly` | `false`     | Read/write (per the #72 "all tools" decision). Flip to `true` to drop every write tool (verified ≈91→61 tools — no PR/issue/file mutation). |
| `X-MCP-Insiders` | `true`      | GitHub's preview/experimental tools (verified ≈91→95 tools). Omit or set `false` for the stable set only.                                   |

Two further `X-MCP-*` toggles are **not** set here but available:

- `X-MCP-Tools` — enable specific _individual_ tools (CSV), a finer-grained alternative to `X-MCP-Toolsets`.
- `X-MCP-Lockdown` — hide public-issue details authored by users without push access (a prompt-injection hardening; consider enabling if untrusted issues are in scope).

(`MCP-Protocol-Version` is an MCP transport header the Claude Code client sets
itself — do not add it to `.mcp.json`.)

> **Why remote (PoC decision).** The issue thread (#72) settled on the **remote
> server with all toolsets** as the proof-of-concept: it is GitHub's recommended
> path, exposes a superset of toolsets vs. local Docker, and needs nothing
> installed beyond a token. Trade-off: repo context transits a hosted GitHub
> service and the token rides in request headers (vs. local Docker's
> GitHub-APIs-only egress).

## Local Docker (offline / air-gapped fallback)

The official [`github/github-mcp-server`](https://github.com/github/github-mcp-server)
(MIT-licensed) can run as a **local Docker container** instead — a strict subset
of the remote toolsets, but no third-party host in the path. Swap the `github`
entry in `.mcp.json` for:

```json
{
  "github": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "--env-file",
      ".env",
      "ghcr.io/github/github-mcp-server"
    ]
  }
}
```

Here Docker reads `.env` directly via `--env-file .env` (so `GITHUB_READ_ONLY` /
`GITHUB_TOOLSETS` in `.env` take effect, and shell vars passed to `docker`
override file values). The `npx @modelcontextprotocol/server-github` variant is
a further no-Docker alternative.

## Cursor IDE

Cursor reads [`.cursor/mcp.json`](../.cursor/mcp.json) — **not** repo-root
`.mcp.json`. The server list mirrors Claude Code's, but Cursor uses its own
[config interpolation](https://cursor.com/docs/mcp#config-interpolation):
`${env:NAME}` (not Claude's `${NAME:-default}` shell form).

**GitHub (remote HTTP).** The `github` server is type `http`; Cursor does **not**
support `envFile` on remote servers — only on stdio. Export
`GITHUB_PERSONAL_ACCESS_TOKEN` into the environment that launches Cursor (or use
GitHub's OAuth flow from Cursor's MCP UI instead of a PAT in config):

```bash
cp .env.example .env
# edit .env, then export before starting Cursor from the same shell:
set -a; . ./.env; set +a
cursor .
```

> **Caveat:** `${env:…}` resolves against the environment Cursor was **launched
> with**, not your shell rc — a Dock/GUI launch won't see vars from `~/.zshrc`,
> so start Cursor via `cursor .` from a shell that has the token exported (or use
> the OAuth flow above). There is no `~/.claude/settings.json`-style `env` block
> for Cursor.

**threat-composer-ai (stdio).** Cursor can load extra vars from `.env` via
`envFile` on stdio servers. Set `AWS_PROFILE` (and optionally `AWS_REGION`) in
your shell or `.env` before use — there is no `${…:-us-east-1}` default in the
Cursor file; rely on your AWS config's default region when unset.

**Agent instructions.** Cursor has no `CURSOR.md` convention. It auto-loads
[`AGENTS.md`](../AGENTS.md) (and `CLAUDE.md` for compatibility). Cursor-specific
setup lives here and in `.cursor/mcp.json`, not a separate instructions file.

**Safeguards (same as Claude):** committed config carries **no secrets** — only
`${env:…}` references; real tokens stay in gitignored `.env` or your shell.
[gitleaks](https://github.com/gitleaks/gitleaks) in pre-commit/CI catches
accidental commits.

## Other editor/agent vendors

`.mcp.json` is read by **Claude Code only**. There is no single cross-agent MCP
file: the `mcpServers` JSON shape ports to Cursor (`.cursor/mcp.json`) and
Gemini CLI (`.gemini/settings.json`), but VS Code/Copilot (`.vscode/mcp.json`)
uses a different key (`servers`) and OpenAI Codex CLI uses TOML
(`~/.codex/config.toml`, `[mcp_servers.<name>]`).

A generator that keeps per-vendor files in sync from one canonical block is
tracked separately ([#111](https://github.com/scottschreckengaust/e2e-ministack/issues/111)).
Until that lands, `.mcp.json` (Claude) and `.cursor/mcp.json` (Cursor) are
maintained in parallel with the same servers but vendor-specific interpolation.
