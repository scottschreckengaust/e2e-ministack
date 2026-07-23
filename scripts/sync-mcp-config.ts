// Generate every per-agent MCP config from the ONE canonical `.mcp.json`
// (issue #111, Phase 2 of the agent-agnostic MCP work #72; Phase 1 = PR #113).
//
// WHY (see docs/MCP.md § Other editor/agent vendors): the repo aims to be
// agent-agnostic, but each agent reads its OWN MCP config path and several use a
// different file shape or env-expansion syntax. Phase 1 kept `.cursor/mcp.json`
// in parallel with `.mcp.json` via a hand-maintained parity check. This module
// replaces that parallel-maintenance with ONE canonical source (`.mcp.json`,
// Claude's `mcpServers` block) that GENERATES each per-agent file — so a server
// added/changed once propagates everywhere, and a CI `git diff --exit-code`
// drift gate (the `sync-mcp-config.mjs check` shim) fails if a committed file
// drifts from the generator output.
//
// LOGIC MODULE (jest-visible, gate-eligible): the pure transforms live here so
// they flow through the repo's 100% coverage gate (#124) + Stryker (#122). The
// runnable CLI is the thin `sync-mcp-config.mjs` shim (read `.mcp.json`,
// write/compare the targets) — Node 24 strips the `.ts` on import, so
// `node scripts/sync-mcp-config.mjs <write|check>` works with no build step.
//
// SECRET-FREE INVARIANT: no target ever materializes a real token. Each agent's
// env-expansion syntax differs and is verified against that agent's official docs
// (docs/MCP.md § Per-agent env-var expansion):
//   Claude   `.mcp.json`            mcpServers  Authorization: `${VAR:-}`   (shell-style default)
//   Cursor   `.cursor/mcp.json`     mcpServers  Authorization: `${env:VAR}` (+ envFile for stdio)
//   VS Code  `.vscode/mcp.json`     servers     Authorization: `${env:VAR}`
//   Gemini   `.gemini/settings.json mcpServers  Authorization: `${VAR}` — httpUrl, NO type field
//   Codex    `.codex/config.toml`   [mcp_servers.*]  bearer_token_env_var + http_headers (HTTP
//                                                    transport FORBIDS env + doesn't ${…}-interpolate)
// Windsurf is global-only (`~/.codeium/windsurf/mcp_config.json`) — documented in
// docs/MCP.md, deliberately not generated (no repo-local file to keep in sync).

import { stringify as tomlStringify } from 'smol-toml';

/** A single MCP server entry in the canonical `.mcp.json`. */
export interface CanonicalServer {
  // stdio transport
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  // Cursor/VS Code load stdio-server defaults from a project .env via this key.
  // Not part of the canonical shape — only added to generated Cursor output.
  envFile?: string;
  // remote HTTP transport
  type?: string;
  url?: string;
  httpUrl?: string; // Gemini's streamable-HTTP field (in place of url/type)
  headers?: Record<string, string>;
}

/** The canonical `.mcp.json` shape (Claude Code project scope). */
export interface CanonicalConfig {
  mcpServers: Record<string, CanonicalServer>;
}

/** The env var carrying the GitHub PAT — the only secret any target references. */
export const TOKEN_VAR = 'GITHUB_PERSONAL_ACCESS_TOKEN';

/**
 * True for a non-null, non-array object (a JSON "map"). Extracted as a single
 * total predicate so the parse guard has no redundant clauses whose mutation
 * would be behaviorally equivalent (an earlier primitive check subsumed by a
 * later property access, etc.).
 */
function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

/**
 * Parse the canonical `.mcp.json` text into a typed config, failing loudly if it
 * is not an object with an `mcpServers` object. Totality guard: a non-object /
 * array / null document (or one whose `mcpServers` is not a plain object) throws
 * a clear error rather than silently generating empty per-agent files.
 */
export function parseCanonical(text: string): CanonicalConfig {
  const raw: unknown = JSON.parse(text);
  if (!isPlainObject(raw) || !isPlainObject(raw.mcpServers)) {
    throw new Error(
      'sync-mcp-config: canonical .mcp.json must be an object with an "mcpServers" object',
    );
  }
  return raw as unknown as CanonicalConfig;
}

// Pretty-print a JSON value the way Prettier formats this repo's JSON: 2-space
// indent + a single trailing newline. Emitting it here (rather than shelling out
// to prettier) keeps the generator dependency-free and its output deterministic;
// the committed files still pass `prettier --check` because this matches
// Prettier's default JSON style.
function jsonFile(value: unknown): string {
  return JSON.stringify(value, null, 2) + '\n';
}

/**
 * Rewrite a canonical `${GITHUB_PERSONAL_ACCESS_TOKEN:-}` Authorization header
 * into a target's own interpolation syntax by swapping the token reference. The
 * canonical value is ALWAYS `Bearer <ref>`; we replace only the `<ref>` so the
 * `Bearer ` prefix and any surrounding text are preserved. `interp` builds the
 * target's reference from the bare var name (e.g. `${env:VAR}` for Cursor/VS Code).
 */
function retargetAuthorization(
  canonicalAuth: string,
  interp: (varName: string) => string,
): string {
  // The canonical form embeds the var name with a shell-style default: match the
  // `${VAR...}` reference (VAR = the token var) and replace the whole reference.
  return canonicalAuth.replace(
    /\$\{GITHUB_PERSONAL_ACCESS_TOKEN[^}]*\}/,
    interp(TOKEN_VAR),
  );
}

/**
 * Rewrite every value in a stdio `env` block through `interp`, preserving the
 * variable NAME but swapping the interpolation syntax. The canonical value is a
 * `${VAR}` or `${VAR:-default}` reference; we extract the bare NAME and re-wrap
 * it in the target's syntax (dropping any default, which only Claude/Gemini
 * express — Cursor loads defaults via envFile instead).
 */
function retargetEnv(
  env: Record<string, string>,
  interp: (varName: string) => string,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    const m = value.match(/\$\{?([A-Za-z_][A-Za-z0-9_]*)/);
    out[key] = m ? interp(m[1]) : value;
  }
  return out;
}

// Deep-copy a server entry so a transform never mutates the caller's canonical
// object (JSON round-trip is fine: these are plain JSON values).
function cloneServer(server: CanonicalServer): CanonicalServer {
  return JSON.parse(JSON.stringify(server)) as CanonicalServer;
}

/**
 * Claude / canonical renderer: re-emit `.mcp.json` verbatim (pretty JSON + a
 * trailing newline). This makes `.mcp.json` itself a generator target so the
 * drift gate also catches a stray hand-edit that leaves it un-normalized, and so
 * the canonical file's formatting is guaranteed identical to the derived files'.
 */
export function renderClaude(c: CanonicalConfig): string {
  return jsonFile({ mcpServers: c.mcpServers });
}

// Shared JSON renderer for the mcpServers-shaped targets (Cursor, VS Code,
// Gemini). `interp` is the target's env-var syntax; `containerKey` is `servers`
// for VS Code, else `mcpServers`; `geminiHttp` rewrites the HTTP transport to
// Gemini's `httpUrl` (no `type`); `withEnvFile` adds Cursor's `envFile`.
function renderJsonTarget(
  c: CanonicalConfig,
  opts: {
    containerKey: 'mcpServers' | 'servers';
    interp: (varName: string) => string;
    geminiHttp: boolean;
    withEnvFile: boolean;
  },
): string {
  const servers: Record<string, CanonicalServer> = {};
  for (const [name, canonical] of Object.entries(c.mcpServers)) {
    const s = cloneServer(canonical);
    if (s.headers?.Authorization) {
      s.headers = {
        ...s.headers,
        Authorization: retargetAuthorization(
          s.headers.Authorization,
          opts.interp,
        ),
      };
    }
    if (s.env) {
      s.env = retargetEnv(s.env, opts.interp);
      if (opts.withEnvFile) s.envFile = '${workspaceFolder}/.env';
    }
    if (opts.geminiHttp && s.url) {
      // Gemini keys its streamable-HTTP endpoint under `httpUrl` and has no
      // `type` field: move url -> httpUrl and drop type.
      s.httpUrl = s.url;
      delete s.url;
      delete s.type;
    }
    servers[name] = s;
  }
  return jsonFile({ [opts.containerKey]: servers });
}

/** Cursor: same `mcpServers` key, `${env:VAR}` syntax, `envFile` for stdio. */
export function renderCursor(c: CanonicalConfig): string {
  return renderJsonTarget(c, {
    containerKey: 'mcpServers',
    interp: (v) => `\${env:${v}}`,
    geminiHttp: false,
    withEnvFile: true,
  });
}

/** VS Code / Copilot: `servers` key, `${env:VAR}` syntax. */
export function renderVscode(c: CanonicalConfig): string {
  return renderJsonTarget(c, {
    containerKey: 'servers',
    interp: (v) => `\${env:${v}}`,
    geminiHttp: false,
    withEnvFile: false,
  });
}

/** Gemini CLI: `mcpServers` key, `${VAR}` syntax, `httpUrl` (no `type`). */
export function renderGemini(c: CanonicalConfig): string {
  return renderJsonTarget(c, {
    containerKey: 'mcpServers',
    interp: (v) => `\${${v}}`,
    geminiHttp: true,
    withEnvFile: false,
  });
}

// A single `[mcp_servers.<name>]` table for the Codex TOML fragment.
interface CodexHttpServer {
  url: string;
  bearer_token_env_var?: string;
  http_headers?: Record<string, string>;
}
interface CodexStdioServer {
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

// Codex banner: terse; the authoring surface + rationale live in docs/MCP.md.
const CODEX_BANNER = [
  '# GENERATED FILE — do NOT edit by hand.',
  '#',
  "# The OpenAI Codex CLI's MCP config, generated from the canonical .mcp.json",
  '# by scripts/sync-mcp-config.ts (#111). Codex reads ~/.codex/config.toml (a',
  '# global file), so this repo-local .codex/config.toml is a REFERENCE FRAGMENT:',
  '# copy its [mcp_servers.*] tables into your ~/.codex/config.toml.',
  '#',
  '# Regenerate: `node scripts/sync-mcp-config.mjs write`. CI fails on drift.',
  '# Secret-free: the github server names the token ENV VAR (bearer_token_env_var)',
  '# — Codex reads GITHUB_PERSONAL_ACCESS_TOKEN from its own environment; no token',
  '# is ever written here. Codex HTTP transport forbids an `env` block and does',
  '# not ${…}-interpolate header strings, so the X-MCP-* toggles are static',
  '# http_headers and the stdio env values are carried verbatim (fill them in via',
  '# your shell/AWS profile).',
].join('\n');

/**
 * Render the Codex `config.toml` fragment: one `[mcp_servers.<name>]` table per
 * canonical server. Codex's transport model differs fundamentally from the JSON
 * agents (verified against openai/codex config sources, see docs/MCP.md):
 *   - HTTP server  -> `url` + `bearer_token_env_var` (names the PAT env var; Codex
 *                     reads it itself) + `http_headers` for the non-secret X-MCP-*
 *                     toggles. NO Authorization header, NO env block (forbidden).
 *   - stdio server -> `command` / `args` / `env` (literal values; Codex does not
 *                     ${…}-expand them — carried verbatim so a human sees the shape).
 * Serialization is delegated to the vetted `smol-toml` (BSD-3-Clause, already a
 * repo devDependency for vex-dialects.ts) so header/env prose can never corrupt
 * the file. Deterministic; ends with a newline.
 */
export function renderCodexToml(c: CanonicalConfig): string {
  const mcp_servers: Record<string, CodexHttpServer | CodexStdioServer> = {};
  for (const [name, s] of Object.entries(c.mcpServers)) {
    if (s.url) {
      const server: CodexHttpServer = { url: s.url };
      server.bearer_token_env_var = TOKEN_VAR;
      // Static headers = every canonical header EXCEPT Authorization (the token,
      // which Codex handles via bearer_token_env_var).
      const httpHeaders: Record<string, string> = {};
      for (const [hk, hv] of Object.entries(s.headers ?? {})) {
        if (hk === 'Authorization') continue;
        httpHeaders[hk] = hv;
      }
      if (Object.keys(httpHeaders).length > 0)
        server.http_headers = httpHeaders;
      mcp_servers[name] = server;
    } else {
      // Build via conditional spread so an absent args/env contributes NO key
      // (rather than an `if (x) obj.x = x` that assigns `undefined` when forced
      // true — a no-op smol-toml drops, i.e. an equivalent mutant). With the
      // spread, `s.args` present vs absent produces DIFFERENT objects.
      mcp_servers[name] = {
        command: String(s.command),
        ...(s.args ? { args: s.args } : {}),
        ...(s.env ? { env: { ...s.env } } : {}),
      };
    }
  }
  // smol-toml terminates its output with exactly one `\n` (same guarantee
  // vex-dialects.ts relies on), so its serialization is already a well-formed
  // POSIX text block — use it verbatim, prepending the banner + a blank line.
  const body = tomlStringify({ mcp_servers });
  return `${CODEX_BANNER}\n\n${body}`;
}

/** One generation target: its committed path and the renderer that produces it. */
export interface Target {
  path: string;
  render: (c: CanonicalConfig) => string;
}

/**
 * The full generation registry: the canonical file + every derived per-agent
 * file. The `.mjs` shim iterates this for both `write` (regenerate) and `check`
 * (drift gate). `.mcp.json` is included so the drift gate also normalizes the
 * canonical file's formatting.
 */
export const TARGETS: readonly Target[] = [
  { path: '.mcp.json', render: renderClaude },
  { path: '.cursor/mcp.json', render: renderCursor },
  { path: '.vscode/mcp.json', render: renderVscode },
  { path: '.gemini/settings.json', render: renderGemini },
  { path: '.codex/config.toml', render: renderCodexToml },
];
