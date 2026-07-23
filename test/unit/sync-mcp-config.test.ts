import {
  parseCanonical,
  renderClaude,
  renderCursor,
  renderVscode,
  renderGemini,
  renderCodexToml,
  TARGETS,
  type CanonicalConfig,
} from '../../scripts/sync-mcp-config';
import { parse as parseToml } from 'smol-toml';

// Unit tests for scripts/sync-mcp-config.ts (issue #111, Phase 2 of #72):
// `.mcp.json` (Claude, `mcpServers`) is the ONE canonical MCP-server block; this
// generator emits every per-agent file from it — Cursor / VS Code / Gemini JSON
// and a Codex `config.toml` fragment — each with that agent's own secret-free
// env-expansion syntax. A CI `git diff --exit-code` drift gate (the `.mjs` shim's
// `check` mode) asserts the committed files match the generator output.
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124) +
// Stryker mutation (#122). The output is security-load-bearing: a transform that
// materialized the token instead of an env reference would leak a secret into a
// committed file, so every renderer is asserted to carry ONLY `${…}`/env-var-name
// references and never a literal `ghp_`/`github_pat_` token.
//
// Env-expansion syntax per target is verified against each agent's official docs
// (see docs/MCP.md § Per-agent env-var expansion): Claude `${VAR:-default}`,
// Cursor/VS Code `${env:VAR}`, Gemini `${VAR}` (+ `httpUrl` not `url`, no `type`),
// Codex `bearer_token_env_var` + `http_headers` (its HTTP transport forbids an
// `env` block and does not `${…}`-interpolate header strings).

// The canonical `.mcp.json` shape the repo ships (two servers: an stdio uvx
// server with an env block, and a remote-HTTP github server with headers).
const CANONICAL: CanonicalConfig = {
  mcpServers: {
    'threat-composer-ai': {
      command: 'uvx',
      args: [
        '--from',
        'git+https://github.com/awslabs/threat-composer.git@0d58a0d85e5413f6c4169245c667ac083f4efb39#subdirectory=packages/threat-composer-ai',
        'threat-composer-ai-mcp',
      ],
      env: {
        AWS_REGION: '${AWS_REGION:-us-east-1}',
        AWS_PROFILE: '${AWS_PROFILE}',
      },
    },
    github: {
      type: 'http',
      url: 'https://api.githubcopilot.com/mcp/',
      headers: {
        Authorization: 'Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN:-}',
        'X-MCP-Toolsets': 'all',
        'X-MCP-Readonly': 'false',
        'X-MCP-Insiders': 'true',
      },
    },
  },
};

const TOKEN_VAR = 'GITHUB_PERSONAL_ACCESS_TOKEN';
// Patterns that would indicate a real materialized token leaked into output.
const REAL_TOKEN_RE = /ghp_[A-Za-z0-9]|github_pat_[A-Za-z0-9]|ghs_[A-Za-z0-9]/;

describe('parseCanonical', () => {
  it('parses the canonical mcpServers block', () => {
    const c = parseCanonical(JSON.stringify(CANONICAL));
    expect(Object.keys(c.mcpServers).sort()).toEqual([
      'github',
      'threat-composer-ai',
    ]);
    expect(c.mcpServers.github.url).toBe('https://api.githubcopilot.com/mcp/');
  });

  it('throws a clear error when mcpServers is missing', () => {
    expect(() => parseCanonical('{}')).toThrow(/mcpServers/);
  });

  // Each distinct rejection path in the `||` guard chain (so a mutant that
  // blanks any single sub-condition fails a test): non-object primitive, null,
  // array, non-object mcpServers, and null mcpServers.
  it('throws on every non-conforming shape', () => {
    expect(() => parseCanonical('"a string"')).toThrow(/mcpServers/);
    expect(() => parseCanonical('42')).toThrow(/mcpServers/);
    expect(() => parseCanonical('null')).toThrow(/mcpServers/);
    expect(() => parseCanonical('[]')).toThrow(/mcpServers/);
    expect(() => parseCanonical('{"mcpServers": "nope"}')).toThrow(
      /mcpServers/,
    );
    expect(() => parseCanonical('{"mcpServers": null}')).toThrow(/mcpServers/);
    expect(() => parseCanonical('{"mcpServers": 7}')).toThrow(/mcpServers/);
    expect(() => parseCanonical('{"mcpServers": []}')).toThrow(/mcpServers/);
  });

  it('accepts an object with an mcpServers object (the positive edge)', () => {
    expect(parseCanonical('{"mcpServers": {}}').mcpServers).toEqual({});
  });
});

describe('renderClaude (canonical round-trip / normalizer)', () => {
  it('re-emits the canonical file verbatim (pretty JSON + trailing newline)', () => {
    const out = renderClaude(CANONICAL);
    // Round-trips: parsing the rendered Claude file yields the same servers.
    const reparsed = parseCanonical(out);
    expect(reparsed.mcpServers).toEqual(CANONICAL.mcpServers);
    expect(out.endsWith('\n')).toBe(true);
  });

  it('preserves the Claude ${VAR:-default} expansion syntax', () => {
    const out = renderClaude(CANONICAL);
    expect(out).toContain('Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN:-}');
    expect(out).toContain('${AWS_REGION:-us-east-1}');
    expect(out).not.toMatch(REAL_TOKEN_RE);
  });
});

describe('renderCursor', () => {
  it('keeps the mcpServers key and rewrites to ${env:VAR} syntax', () => {
    const out = renderCursor(CANONICAL);
    const obj = JSON.parse(out);
    expect(Object.keys(obj)).toEqual(['mcpServers']);
    expect(obj.mcpServers.github.type).toBe('http');
    expect(obj.mcpServers.github.url).toBe(CANONICAL.mcpServers.github.url);
    expect(obj.mcpServers.github.headers.Authorization).toBe(
      `Bearer \${env:${TOKEN_VAR}}`,
    );
    // Non-Authorization headers copied verbatim.
    expect(obj.mcpServers.github.headers['X-MCP-Toolsets']).toBe('all');
  });

  it('rewrites the stdio env block to ${env:VAR} and adds envFile', () => {
    const out = renderCursor(CANONICAL);
    const obj = JSON.parse(out);
    expect(obj.mcpServers['threat-composer-ai'].env).toEqual({
      AWS_REGION: '${env:AWS_REGION}',
      AWS_PROFILE: '${env:AWS_PROFILE}',
    });
    expect(obj.mcpServers['threat-composer-ai'].envFile).toBe(
      '${workspaceFolder}/.env',
    );
    // command/args copied verbatim.
    expect(obj.mcpServers['threat-composer-ai'].command).toBe('uvx');
    expect(obj.mcpServers['threat-composer-ai'].args).toEqual(
      CANONICAL.mcpServers['threat-composer-ai'].args,
    );
  });

  it('never emits a real token and ends with a newline', () => {
    const out = renderCursor(CANONICAL);
    expect(out).not.toMatch(REAL_TOKEN_RE);
    expect(out.endsWith('\n')).toBe(true);
  });
});

describe('renderVscode', () => {
  it('renames mcpServers -> servers (VS Code key) with ${env:VAR}', () => {
    const out = renderVscode(CANONICAL);
    const obj = JSON.parse(out);
    expect(Object.keys(obj)).toEqual(['servers']);
    expect(obj.servers.github.type).toBe('http');
    expect(obj.servers.github.url).toBe(CANONICAL.mcpServers.github.url);
    expect(obj.servers.github.headers.Authorization).toBe(
      `Bearer \${env:${TOKEN_VAR}}`,
    );
    expect(obj.servers['threat-composer-ai'].env).toEqual({
      AWS_REGION: '${env:AWS_REGION}',
      AWS_PROFILE: '${env:AWS_PROFILE}',
    });
  });

  it('never emits a real token and ends with a newline', () => {
    const out = renderVscode(CANONICAL);
    expect(out).not.toMatch(REAL_TOKEN_RE);
    expect(out.endsWith('\n')).toBe(true);
  });
});

describe('renderGemini', () => {
  it('keeps mcpServers, uses httpUrl (not url/type) and ${VAR} syntax', () => {
    const out = renderGemini(CANONICAL);
    const obj = JSON.parse(out);
    expect(Object.keys(obj)).toEqual(['mcpServers']);
    // Gemini's streamable-HTTP field is `httpUrl`; it has no `type` field.
    expect(obj.mcpServers.github.httpUrl).toBe(CANONICAL.mcpServers.github.url);
    expect(obj.mcpServers.github.url).toBeUndefined();
    expect(obj.mcpServers.github.type).toBeUndefined();
    expect(obj.mcpServers.github.headers.Authorization).toBe(
      `Bearer \${${TOKEN_VAR}}`,
    );
    // Gemini expands ${VAR} in the stdio env block too.
    expect(obj.mcpServers['threat-composer-ai'].env).toEqual({
      AWS_REGION: '${AWS_REGION}',
      AWS_PROFILE: '${AWS_PROFILE}',
    });
  });

  it('never emits a real token and ends with a newline', () => {
    const out = renderGemini(CANONICAL);
    expect(out).not.toMatch(REAL_TOKEN_RE);
    expect(out.endsWith('\n')).toBe(true);
  });
});

describe('renderCodexToml', () => {
  it('emits [mcp_servers.*] tables parseable as TOML', () => {
    const out = renderCodexToml(CANONICAL);
    const obj = parseToml(out) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    expect(Object.keys(obj.mcp_servers).sort()).toEqual([
      'github',
      'threat-composer-ai',
    ]);
  });

  it('maps the github HTTP server to url + bearer_token_env_var + http_headers', () => {
    const out = renderCodexToml(CANONICAL);
    const obj = parseToml(out) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    const gh = obj.mcp_servers.github;
    expect(gh.url).toBe(CANONICAL.mcpServers.github.url);
    // Codex reads the bearer token from the named env var itself (no ${…}).
    expect(gh.bearer_token_env_var).toBe(TOKEN_VAR);
    // The non-Authorization X-MCP-* headers become static http_headers.
    expect(gh.http_headers).toEqual({
      'X-MCP-Toolsets': 'all',
      'X-MCP-Readonly': 'false',
      'X-MCP-Insiders': 'true',
    });
    // Codex HTTP transport forbids an env block and has no Authorization header key.
    expect(gh.env).toBeUndefined();
    expect(gh.headers).toBeUndefined();
  });

  it('maps the stdio server to command/args/env (literal env values)', () => {
    const out = renderCodexToml(CANONICAL);
    const obj = parseToml(out) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    const tc = obj.mcp_servers['threat-composer-ai'];
    expect(tc.command).toBe('uvx');
    expect(tc.args).toEqual(CANONICAL.mcpServers['threat-composer-ai'].args);
    // Codex does not ${…}-expand stdio env values; carry the canonical strings
    // verbatim so a human sees exactly what to fill in (still no real secret).
    expect(tc.env).toEqual({
      AWS_REGION: '${AWS_REGION:-us-east-1}',
      AWS_PROFILE: '${AWS_PROFILE}',
    });
  });

  it('carries a GENERATED banner, no real token, and a trailing newline', () => {
    const out = renderCodexToml(CANONICAL);
    expect(out).toContain('GENERATED');
    expect(out).toContain(TOKEN_VAR);
    expect(out).not.toMatch(REAL_TOKEN_RE);
    expect(out.endsWith('\n')).toBe(true);
  });

  it('is deterministic (same input -> byte-identical output)', () => {
    expect(renderCodexToml(CANONICAL)).toBe(renderCodexToml(CANONICAL));
  });
});

describe('edge cases (totality of the transforms)', () => {
  // An HTTP server carrying ONLY an Authorization header (no X-MCP-* toggles) —
  // Codex must then emit NO http_headers table (all headers were the secret).
  const AUTH_ONLY: CanonicalConfig = {
    mcpServers: {
      github: {
        type: 'http',
        url: 'https://example/mcp/',
        headers: { Authorization: 'Bearer ${GITHUB_PERSONAL_ACCESS_TOKEN:-}' },
      },
    },
  };

  // An HTTP server with NO headers block at all, and a stdio server with no
  // args/env — exercises the `?? {}` / optional-copy branches. Plus a stdio env
  // value that is a plain literal (no `$` reference) → retargetEnv fallback, and
  // a bare `$VAR` (no-brace) reference → the regex's optional `{?` branch.
  const BARE: CanonicalConfig = {
    mcpServers: {
      remote: { type: 'http', url: 'https://example/bare/' },
      local: { command: 'run-it' },
      literal: {
        command: 'x',
        env: { PLAIN: 'no-dollar-here', NOBRACE: '$SHELL_STYLE' },
      },
      // An HTTP server whose only header is a NON-Authorization header — the
      // JSON targets must copy it verbatim and NOT inject an Authorization key.
      headed: {
        type: 'http',
        url: 'https://example/headed/',
        headers: { 'X-Custom': 'v' },
      },
    },
  };

  it('Codex omits http_headers when only Authorization is present', () => {
    const out = renderCodexToml(AUTH_ONLY);
    const obj = parseToml(out) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    expect(obj.mcp_servers.github.bearer_token_env_var).toBe(TOKEN_VAR);
    expect(obj.mcp_servers.github.http_headers).toBeUndefined();
  });

  it('Codex tolerates a headerless HTTP server and argless/envless stdio server', () => {
    const out = renderCodexToml(BARE);
    const obj = parseToml(out) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    expect(obj.mcp_servers.remote.url).toBe('https://example/bare/');
    expect(obj.mcp_servers.remote.http_headers).toBeUndefined();
    expect(obj.mcp_servers.local.command).toBe('run-it');
    expect(obj.mcp_servers.local.args).toBeUndefined();
    expect(obj.mcp_servers.local.env).toBeUndefined();
  });

  it('JSON targets copy a non-interpolated env value through verbatim', () => {
    const cursor = JSON.parse(renderCursor(BARE));
    expect(cursor.mcpServers.literal.env.PLAIN).toBe('no-dollar-here');
    const gemini = JSON.parse(renderGemini(BARE));
    expect(gemini.mcpServers.literal.env.PLAIN).toBe('no-dollar-here');
  });

  it('retargets a bare $VAR (no-brace) env reference by name', () => {
    // The regex must match the optional `{`: `$SHELL_STYLE` -> the target syntax
    // wrapping the bare NAME. Cursor -> ${env:SHELL_STYLE}, Gemini -> ${SHELL_STYLE}.
    expect(JSON.parse(renderCursor(BARE)).mcpServers.literal.env.NOBRACE).toBe(
      '${env:SHELL_STYLE}',
    );
    expect(JSON.parse(renderGemini(BARE)).mcpServers.literal.env.NOBRACE).toBe(
      '${SHELL_STYLE}',
    );
  });

  it('does NOT inject Authorization into a server that has none', () => {
    for (const render of [renderCursor, renderVscode, renderGemini]) {
      const obj = JSON.parse(render(BARE));
      const servers = obj.mcpServers ?? obj.servers;
      expect(servers.headed.headers).toEqual({ 'X-Custom': 'v' });
      expect(servers.headed.headers.Authorization).toBeUndefined();
      // A server with no headers block at all stays headerless.
      expect(servers.remote.headers).toBeUndefined();
    }
  });

  it('adds envFile ONLY for Cursor (not VS Code / Gemini)', () => {
    expect(JSON.parse(renderCursor(BARE)).mcpServers.literal.envFile).toBe(
      '${workspaceFolder}/.env',
    );
    expect(
      JSON.parse(renderVscode(BARE)).servers.literal.envFile,
    ).toBeUndefined();
    expect(
      JSON.parse(renderGemini(BARE)).mcpServers.literal.envFile,
    ).toBeUndefined();
  });

  it('rewrites HTTP transport to httpUrl ONLY for Gemini (Cursor/VS Code keep url+type)', () => {
    // Gemini: httpUrl, no url/type.
    const g = JSON.parse(renderGemini(BARE)).mcpServers.remote;
    expect(g.httpUrl).toBe('https://example/bare/');
    expect(g.url).toBeUndefined();
    expect(g.type).toBeUndefined();
    // Cursor + VS Code: keep url + type, no httpUrl.
    const cu = JSON.parse(renderCursor(BARE)).mcpServers.remote;
    expect(cu.url).toBe('https://example/bare/');
    expect(cu.type).toBe('http');
    expect(cu.httpUrl).toBeUndefined();
    const vs = JSON.parse(renderVscode(BARE)).servers.remote;
    expect(vs.url).toBe('https://example/bare/');
    expect(vs.type).toBe('http');
    expect(vs.httpUrl).toBeUndefined();
  });

  it('Codex includes args when present and omits them when absent', () => {
    const withArgs: CanonicalConfig = {
      mcpServers: { s: { command: 'c', args: ['--flag'] } },
    };
    const objWith = parseToml(renderCodexToml(withArgs)) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    expect(objWith.mcp_servers.s.args).toEqual(['--flag']);
    // BARE.local has no args → the TOML table must not carry an args key.
    const objBare = parseToml(renderCodexToml(BARE)) as {
      mcp_servers: Record<string, Record<string, unknown>>;
    };
    expect(objBare.mcp_servers.local.args).toBeUndefined();
  });

  it('Codex emits the exact GENERATED banner verbatim (every line load-bearing)', () => {
    // Compare the full banner block byte-for-byte against a LITERAL expected
    // string held in the test (not imported), so a mutant that blanks ANY banner
    // line — including the bare `#` separators — fails this assertion. The banner
    // is load-bearing: it tells a human the file is generated, secret-free, and
    // how/where to use the fragment (copy tables into ~/.codex/config.toml).
    const EXPECTED_BANNER = [
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
    expect(
      renderCodexToml(CANONICAL).startsWith(EXPECTED_BANNER + '\n\n'),
    ).toBe(true);
  });
});

describe('TARGETS registry', () => {
  it('maps every per-agent output path to a renderer', () => {
    const paths = TARGETS.map((t) => t.path).sort();
    expect(paths).toEqual([
      '.codex/config.toml',
      '.cursor/mcp.json',
      '.gemini/settings.json',
      '.mcp.json',
      '.vscode/mcp.json',
    ]);
    for (const t of TARGETS) {
      const out = t.render(CANONICAL);
      expect(typeof out).toBe('string');
      expect(out).not.toMatch(REAL_TOKEN_RE);
      expect(out.endsWith('\n')).toBe(true);
    }
  });
});
