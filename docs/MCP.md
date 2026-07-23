# MCP servers

This repo ships a repo-wide [Model Context Protocol](https://modelcontextprotocol.io)
configuration in [`.mcp.json`](../.mcp.json) (the Claude Code / CLI location) so an
agent can interact with the project and the GitHub repository.

> **Scope.** `.mcp.json` is the **Claude Code** project-scope file and the ONE
> canonical source. Every other agent's config
> (`.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`)
> is **generated** from it by `scripts/sync-mcp-config.ts` — see
> [Canonical source + generator](#canonical-source--generator).

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

### GitHub remote headers (all agents)

Every agent's `github` entry sends the same four headers. Only the token
reference differs per agent's env-expansion syntax (see
[Per-agent env-var expansion](#per-agent-env-var-expansion)); the generator emits
each correctly from the one canonical value in [`.mcp.json`](../.mcp.json).

GitHub's remote server takes the `Authorization` header (the only secret) plus five
optional `X-MCP-*` toggles ([authoritative list](https://github.com/github/github-mcp-server/blob/main/docs/remote-server.md#optional-headers)).
This PoC sets four:

| Header           | Value (PoC) | Effect                                                                                                                                      |
| ---------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Authorization`  | from env    | `Bearer <PAT>` — the only secret; see token loaders below.                                                                                  |
| `X-MCP-Toolsets` | `all`       | Toolset groups to expose. Narrow it (e.g. `repos,issues,pull_requests`) to shrink the surface area.                                         |
| `X-MCP-Readonly` | `false`     | Read/write (per the #72 "all tools" decision). Flip to `true` to drop every write tool (verified ≈91→61 tools — no PR/issue/file mutation). |
| `X-MCP-Insiders` | `true`      | GitHub's preview/experimental tools (verified ≈91→95 tools). Omit or set `false` for the stable set only.                                   |

Two further `X-MCP-*` toggles are **not** set in either file but available:

- `X-MCP-Tools` — enable specific _individual_ tools (CSV), a finer-grained alternative to `X-MCP-Toolsets`.
- `X-MCP-Lockdown` — hide public-issue details authored by users without push access (a prompt-injection hardening; consider enabling if untrusted issues are in scope).

(`MCP-Protocol-Version` is an MCP transport header the client sets itself — do not
add it to committed MCP JSON.)

**Drift gate:** `npm run check:mcp-parity` (`scripts/sync-mcp-config.mjs check`)
regenerates every per-agent file from `.mcp.json` in memory and fails CI (unit
job) and pre-commit if a committed file drifts — see
[Canonical source + generator](#canonical-source--generator).

> **Why remote (PoC decision).** The issue thread (#72) settled on the **remote
> server with all toolsets** as the proof-of-concept: it is GitHub's recommended
> path, exposes a superset of toolsets vs. local Docker, and needs nothing
> installed beyond a token. Trade-off: repo context transits a hosted GitHub
> service and the token rides in request headers (vs. local Docker's
> GitHub-APIs-only egress).

## Local Docker (offline / air-gapped fallback)

The official [`github/github-mcp-server`](https://github.com/github/github-mcp-server)
(MIT-licensed) can run as a **local Docker container** instead — a strict subset
of the remote toolsets, but no third-party host in the path.

**Claude** — swap the `github` entry in `.mcp.json` for:

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

**Cursor** — swap the `github` entry in `.cursor/mcp.json` for:

```json
{
  "github": {
    "command": "docker",
    "args": [
      "run",
      "-i",
      "--rm",
      "--env-file",
      "${workspaceFolder}/.env",
      "ghcr.io/github/github-mcp-server"
    ]
  }
}
```

Docker reads `.env` via `--env-file` (so `GITHUB_READ_ONLY` / `GITHUB_TOOLSETS`
take effect; shell vars passed to `docker` override file values). The
`npx @modelcontextprotocol/server-github` variant is a further no-Docker alternative.

## Cursor IDE

Cursor reads [`.cursor/mcp.json`](../.cursor/mcp.json) — **not** repo-root
`.mcp.json`. The server list and GitHub headers mirror Claude Code; Cursor uses
[config interpolation](https://cursor.com/docs/mcp#config-interpolation):
`${env:NAME}` (not Claude's `${NAME:-default}` shell form).

### Token loaders (pick one — never commit a real token)

| Path                                                                        | GUI launch                      | CLI (`cursor` / `cursor-agent`) | Notes                                                                                                                                                                                                        |
| --------------------------------------------------------------------------- | ------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Shell export + `cursor .`                                                   | Only if started from that shell | Yes                             | `set -a; . ./.env; set +a` then `cursor .`                                                                                                                                                                   |
| [`~/.cursor/mcp.json`](https://cursor.com/docs/mcp#configuration-locations) | **Yes**                         | **Yes**                         | Global user config; merges with project `.cursor/mcp.json`. Copy [docs/mcp-global-cursor.example.json](mcp-global-cursor.example.json) and set the token via `${env:…}` or a user-local literal (see below). |
| Project `.env` + `envFile`                                                  | No (HTTP)                       | Partial                         | Works for **stdio** servers only (`threat-composer-ai`); remote `github` HTTP does **not** read `envFile`.                                                                                                   |
| Cursor MCP UI OAuth                                                         | Yes                             | Yes                             | No PAT in config; GitHub-hosted OAuth flow.                                                                                                                                                                  |

```bash
cp .env.example .env
# edit GITHUB_PERSONAL_ACCESS_TOKEN (and AWS_* if using threat-composer-ai)
set -a; . ./.env; set +a
cursor .
```

> **GUI caveat:** `${env:…}` resolves against the environment **Cursor was launched
> with**, not your shell rc — Dock/Spotlight won't see `~/.zshrc` exports. For GUI
> launches use **`~/.cursor/mcp.json`**, OAuth, or start Cursor from a shell that
> already exported the token.

**`~/.cursor/mcp.json` (recommended for GUI).** User-local file (never in this
repo). Two patterns:

1. **Env interpolation (preferred)** — same shape as
   [docs/mcp-global-cursor.example.json](mcp-global-cursor.example.json). Still needs
   `GITHUB_PERSONAL_ACCESS_TOKEN` in the OS environment unless you use pattern (2).
2. **Literal Bearer (user machine only)** — replace `${env:GITHUB_PERSONAL_ACCESS_TOKEN}`
   with `ghp_…` in `~/.cursor/mcp.json` only. `chmod 600`; never commit. Works for
   both GUI and CLI because Cursor reads the global file at startup.

Project `.cursor/mcp.json` stays secret-free; global file supplies auth for all
workspaces when the GUI launch path can't see your shell.

**threat-composer-ai (stdio).** Cursor loads `.env` via `envFile` on stdio servers.
Set `AWS_PROFILE` and optionally `AWS_REGION` in `.env` (see `.env.example`) — there
is no `${…:-us-east-1}` default in the Cursor file.

### Verify (PoC)

After supplying a valid `GITHUB_PERSONAL_ACCESS_TOKEN`:

1. `npm run check:mcp-parity` — committed Claude/Cursor configs match.
2. Open this repo in Cursor; **Settings → MCP** (or Agent MCP list) — `github` and
   `threat-composer-ai` should appear.
3. Enable `github` — expect on the order of **~91 tools** with this PoC's headers
   (≈95 with Insiders). A **401** means the token is missing, revoked, or not visible
   to the Cursor process (common with GUI launch — use `~/.cursor/mcp.json` or OAuth).
4. `threat-composer-ai` requires `uvx`, Bedrock-capable `AWS_PROFILE`, and explicit
   approval in the MCP UI — optional; never runs in CI.

**Agent instructions.** Cursor has no `CURSOR.md` convention. It auto-loads
[`AGENTS.md`](../AGENTS.md) (and `CLAUDE.md` for compatibility). Cursor-specific
setup lives here and in `.cursor/mcp.json`, not a separate instructions file.

**Safeguards (same as Claude):** committed config carries **no secrets** — only
`${env:…}` references; real tokens stay in gitignored `.env`, user-global
`~/.cursor/mcp.json`, or OAuth. [gitleaks](https://github.com/gitleaks/gitleaks) in
pre-commit/CI catches accidental commits.

## Canonical source + generator

`.mcp.json` (Claude Code, `mcpServers`) is the **one canonical source**. Every
other agent reads its own path with its own file shape and env-expansion syntax,
so `scripts/sync-mcp-config.ts` **generates** each per-agent file from `.mcp.json`
(the transform logic is unit-tested + 100%-coverage-gated + Stryker-mutated like
the repo's other logic modules; the runnable CLI is the thin
`scripts/sync-mcp-config.mjs` shim). Add or change a server ONCE in `.mcp.json`,
then regenerate:

```bash
npm run sync:mcp-config   # (re)write every per-agent file from .mcp.json
npm run check:mcp-parity  # drift gate: fail if a committed file != generator output
```

**Generated targets** (all committed, all secret-free — see
[Per-agent env-var expansion](#per-agent-env-var-expansion)):

| Agent           | File                    | Server key        | HTTP transport                                  | Token reference                              |
| --------------- | ----------------------- | ----------------- | ----------------------------------------------- | -------------------------------------------- |
| Claude Code     | `.mcp.json` (canonical) | `mcpServers`      | `type: http` + `url`                            | `Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN:-}`   |
| Cursor          | `.cursor/mcp.json`      | `mcpServers`      | `type: http` + `url`                            | `Bearer ${env:GITHUB_PERSONAL_ACCESS_TOKEN}` |
| VS Code/Copilot | `.vscode/mcp.json`      | `servers`         | `type: http` + `url`                            | `Bearer ${env:GITHUB_PERSONAL_ACCESS_TOKEN}` |
| Gemini CLI      | `.gemini/settings.json` | `mcpServers`      | `httpUrl` (no `type`)                           | `Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN}`     |
| OpenAI Codex    | `.codex/config.toml`    | `[mcp_servers.*]` | `url` + `bearer_token_env_var` + `http_headers` | `bearer_token_env_var = "GITHUB_…TOKEN"`     |

**Drift gate.** `npm run check:mcp-parity` (`sync-mcp-config.mjs check`) regenerates
all targets in memory and fails — in the CI unit job and the `mcp-config-drift`
pre-commit hook — if any committed file differs. A hand-edit or a forgotten
`sync:mcp-config` can never silently desync an agent from the canonical block.

**Codex is a reference fragment, not a repo config.** Codex reads a **global**
`~/.codex/config.toml`, so the committed `.codex/config.toml` is a fragment to copy
its `[mcp_servers.*]` tables from (the file's banner says so). Its HTTP transport
model differs fundamentally: it forbids a per-server `env` block and does **not**
`${…}`-interpolate header strings, so the token is named via `bearer_token_env_var`
(Codex reads `GITHUB_PERSONAL_ACCESS_TOKEN` from its own environment) and the
`X-MCP-*` toggles become static `http_headers`.

**Windsurf** is **global-only** (`~/.codeium/windsurf/mcp_config.json`, no
repo-local file), so it is documented here but deliberately **not** generated —
there is no committed file to keep in sync. Copy the `mcpServers` block from
`.mcp.json` into that global file and use Windsurf's own token loader.

## Per-agent env-var expansion

The token (`GITHUB_PERSONAL_ACCESS_TOKEN`) is the only secret; **no committed file
ever holds a real token** — each carries only a reference in that agent's syntax
(verified against each vendor's official docs):

- **Claude** — shell-style `${VAR}` / `${VAR:-default}`, expanded from Claude's launch environment.
- **Cursor** — [`${env:VAR}`](https://cursor.com/docs/mcp#config-interpolation); stdio-server defaults load via `envFile`.
- **VS Code** — `${env:VAR}` (same predefined-variable syntax as `launch.json`); `${input:…}` prompts are the alternative for secrets.
- **Gemini CLI** — `$VAR` / `${VAR}` / `${VAR:-default}` in any `settings.json` string; note Gemini keys streamable-HTTP under **`httpUrl`** (not `url`/`type`).
- **Codex** — no `${…}` interpolation. The HTTP server names the token env var via `bearer_token_env_var`; stdio `env` values are carried **verbatim** (Codex does not expand them — fill them in via your shell/AWS profile).

gitleaks (pre-commit + CI, full history) catches an accidentally committed real token.
