import { execFileSync } from 'node:child_process';
import * as path from 'node:path';

// TDD tests for scripts/ministack-upstream.mjs (#137, sub-issue C of epic
// #117): upstream MiniStack tracking. The script's core principle is
// query = automated, comment/watch = HUMAN-GATED. It may READ upstream freely
// (gh search) and WRITE to OUR registry, but it NEVER auto-posts/subscribes to
// the foreign repo — draft-comment only PRINTS a copy-pasteable command.
//
// This suite locks two things:
//   1. the never-auto-post safety property (the #1 thing to get right), and
//   2. the pure match/format logic (offline, from a fixture — no network).
//
// The pure logic is exercised through the ESM export surface (imported via a
// spawned Node harness that dynamic-imports the .mjs and prints JSON), and the
// CLI contract is exercised by spawning the script directly — the exact style
// of test/unit/license-verdict.test.ts. Network I/O (the real `gh search`) is
// kept OUT of the pure functions, so this suite runs fully offline.
const SCRIPT = path.resolve(__dirname, '../../scripts/ministack-upstream.mjs');

/**
 * Run the script CLI with argv and capture stdout + exit code, mirroring
 * license-verdict.test.ts. `draft-comment` never touches the network and never
 * posts (its only child_process use is the read-only `gh search` on the `query`
 * path), so these runs are safe and offline.
 */
interface Run {
  code: number;
  stdout: string;
  stderr: string;
}
function run(args: string[]): Run {
  try {
    const stdout = execFileSync(process.execPath, [SCRIPT, ...args], {
      encoding: 'utf8',
    });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as {
      status: number | null;
      stdout?: string;
      stderr?: string;
    };
    return {
      code: e.status ?? -1,
      stdout: String(e.stdout ?? ''),
      stderr: String(e.stderr ?? ''),
    };
  }
}

/**
 * Evaluate a tiny JS snippet in a child Node that dynamic-imports the .mjs, so
 * we can exercise the exported pure functions from this CJS ts-jest env
 * (jest's VM would need --experimental-vm-modules for a direct import()). The
 * snippet prints a JSON line we parse back.
 */
function callExport(snippet: string): unknown {
  const program = `
    import * as m from ${JSON.stringify(SCRIPT)};
    const out = (${snippet});
    process.stdout.write(JSON.stringify(out));
  `;
  const stdout = execFileSync(
    process.execPath,
    ['--input-type=module', '-e', program],
    {
      encoding: 'utf8',
    },
  );
  return JSON.parse(stdout);
}

// A representative `gh search issues/prs --json number,title,url,state` payload
// (the AgentCore case). We do NOT hit the network — this is the fixture the
// pure selection logic runs against.
const AGENTCORE_ISSUES = [
  {
    number: 1021,
    state: 'open',
    title: 'New service emulator — Amazon Bedrock AgentCore',
    url: 'https://github.com/ministackorg/ministack/issues/1021',
  },
];

describe('ministack-upstream — never-auto-post safety property', () => {
  it('exports AUTO_POST_UPSTREAM defaulting to false (the single gate)', () => {
    expect(callExport('m.AUTO_POST_UPSTREAM')).toBe(false);
  });

  it('draft-comment PRINTS a copy-pasteable gh command and never posts', () => {
    const res = run(['draft-comment', 'agentcore']);
    expect(res.code).toBe(0);
    // The exact post command a human copies — proves we hand off, not post.
    expect(res.stdout).toContain(
      'gh issue comment ministackorg/ministack#1021 --repo ministackorg/ministack',
    );
    // A one-click URL is also offered.
    expect(res.stdout).toContain('https://github.com/ministackorg/ministack');
    // Loud, unambiguous statement that nothing was posted.
    expect(res.stdout).toMatch(
      /never auto-post|NOT posted|no comment was posted/i,
    );
    // Belt and braces: nowhere does the default path claim to have posted.
    expect(res.stdout).not.toMatch(
      /comment posted|posted to upstream|subscribed/i,
    );
  });

  it('draft-comment for an unmatched service still never posts (dsql → no ref)', () => {
    const res = run(['draft-comment', 'dsql']);
    // dsql has ministackRef null — no upstream issue to comment on yet; the
    // script drafts a NEW-issue ask instead, still human-gated, still no post.
    expect(res.code).toBe(0);
    expect(res.stdout).toMatch(
      /never auto-post|NOT posted|no comment was posted/i,
    );
    expect(res.stdout).not.toMatch(
      /comment posted|posted to upstream|subscribed/i,
    );
  });
});

describe('ministack-upstream — pure match/format logic (offline fixture)', () => {
  it('selects the best upstream match from a gh search payload', () => {
    const match = callExport(
      `m.selectBestMatch(${JSON.stringify(AGENTCORE_ISSUES)}, [], 'agentcore')`,
    );
    expect(match).toMatchObject({ number: 1021 });
  });

  it('formats a matched result as owner/repo#N', () => {
    const ref = callExport(
      `m.formatRef(${JSON.stringify(AGENTCORE_ISSUES[0])})`,
    );
    expect(ref).toBe('ministackorg/ministack#1021');
  });

  it('returns null (→ no ref) when nothing matches (the DSQL case)', () => {
    const match = callExport(`m.selectBestMatch([], [], 'dsql')`);
    expect(match).toBeNull();
    const ref = callExport(`m.formatRef(null)`);
    expect(ref).toBeNull();
  });

  it('prefers an OPEN issue over a CLOSED one, and a title hit over a body-only hit', () => {
    const results = [
      {
        number: 10,
        state: 'closed',
        title: 'agentcore old proposal',
        url: 'https://github.com/ministackorg/ministack/issues/10',
      },
      {
        number: 20,
        state: 'open',
        title: 'New service emulator — Amazon Bedrock AgentCore',
        url: 'https://github.com/ministackorg/ministack/issues/20',
      },
      {
        number: 5,
        state: 'open',
        title: 'unrelated networking thing',
        url: 'https://github.com/ministackorg/ministack/issues/5',
      },
    ];
    const match = callExport(
      `m.selectBestMatch(${JSON.stringify(results)}, [], 'agentcore')`,
    ) as { number: number };
    // #20: open + title contains the service name → best.
    expect(match.number).toBe(20);
  });

  it('drafts a structured comment body carrying the digest, verdict, and ask', () => {
    const body = callExport(
      `m.draftCommentBody({ service: 'agentcore', status: 'upstream-tracked', ministackRef: 'ministackorg/ministack#1021' }, 'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef')`,
    ) as string;
    expect(body).toContain('agentcore');
    expect(body).toContain('upstream-tracked');
    // The MiniStack image digest it was verified against.
    expect(body).toContain(
      'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
    );
    // An explicit ask so the maintainer knows what the comment requests.
    expect(body.toLowerCase()).toMatch(/ask|would|please|request/);
  });

  it('builds the exact copy-pasteable post command for a known ref', () => {
    const cmd = callExport(
      `m.formatPostCommand('ministackorg/ministack#1021', 'hello body')`,
    ) as string;
    expect(cmd).toContain(
      'gh issue comment ministackorg/ministack#1021 --repo ministackorg/ministack',
    );
    expect(cmd).toContain('--body');
  });

  it('validates a service name (rejects shell-metachar injection)', () => {
    // The service arg must never carry shell metacharacters into any execFile.
    expect(callExport(`m.isValidServiceName('agentcore')`)).toBe(true);
    expect(callExport(`m.isValidServiceName('rds-postgres')`)).toBe(true);
    expect(callExport(`m.isValidServiceName('a; rm -rf /')`)).toBe(false);
    expect(callExport(`m.isValidServiceName('$(whoami)')`)).toBe(false);
    expect(callExport(`m.isValidServiceName('')`)).toBe(false);
  });
});

describe('ministack-upstream — CLI contract', () => {
  it('exits 2 with usage on an unknown subcommand', () => {
    const res = run(['frobnicate']);
    expect(res.code).toBe(2);
    expect(res.stderr + res.stdout).toMatch(/usage/i);
  });

  it('exits 2 with usage when no subcommand is given', () => {
    const res = run([]);
    expect(res.code).toBe(2);
    expect(res.stderr + res.stdout).toMatch(/usage/i);
  });

  it('exits 2 on an invalid service name', () => {
    const res = run(['draft-comment', 'a; rm -rf /']);
    expect(res.code).toBe(2);
    expect(res.stderr + res.stdout).toMatch(/invalid service/i);
  });
});
