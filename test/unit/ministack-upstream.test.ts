import { execFileSync } from 'node:child_process';
import * as path from 'node:path';
import {
  AUTO_POST_UPSTREAM,
  UPSTREAM_REPO,
  draftCommentBody,
  formatOneClickUrl,
  formatPostCommand,
  formatRef,
  isValidServiceName,
  selectBestMatch,
} from '../../scripts/ministack-upstream';

// Unit tests for scripts/ministack-upstream.ts (#137, sub-issue C of epic #117;
// gated under #165). The tracker's core principle is
// query = automated, comment/watch = HUMAN-GATED. It may READ upstream freely
// (gh search) and WRITE to OUR registry, but it NEVER auto-posts/subscribes to
// the foreign repo — draft-comment only PRINTS a copy-pasteable command.
//
// The PURE logic (ranking, formatting, the AUTO_POST_UPSTREAM gate) is
// exercised by importing the .ts module IN-PROCESS so it flows through the
// 100% coverage gate (#124) + Stryker mutation (#122). (The old suite spawned
// the .mjs CLI / a child-Node dynamic import, which istanbul/Stryker cannot
// instrument, so the pure logic was silently ungated.) A tail of CLI tests
// still spawns the thin `.mjs` shim to lock the never-auto-post safety property
// and the argv/exit-code contract against the real Node-24 `.ts` import.
const SCRIPT = path.resolve(__dirname, '../../scripts/ministack-upstream.mjs');

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
    expect(AUTO_POST_UPSTREAM).toBe(false);
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

describe('ministack-upstream — pure match/format logic (offline, in-process)', () => {
  it('selects the best upstream match from a gh search payload', () => {
    const match = selectBestMatch(AGENTCORE_ISSUES, [], 'agentcore');
    expect(match).toMatchObject({ number: 1021 });
  });

  it('formats a matched result as owner/repo#N', () => {
    expect(formatRef(AGENTCORE_ISSUES[0])).toBe('ministackorg/ministack#1021');
  });

  it('returns null (→ no ref) when nothing matches (the DSQL case)', () => {
    expect(selectBestMatch([], [], 'dsql')).toBeNull();
    expect(formatRef(null)).toBeNull();
    // Undefined/missing-number inputs also collapse to null.
    expect(formatRef(undefined)).toBeNull();
    expect(formatRef({})).toBeNull();
  });

  it('treats nullish issues/prs lists as empty (no candidates → null)', () => {
    // Guards the `issues ?? []` / `prs ?? []` branches.
    expect(selectBestMatch(null, null, 'agentcore')).toBeNull();
    expect(selectBestMatch(undefined, undefined, 'agentcore')).toBeNull();
    // A match still comes through when only ONE list is nullish.
    expect(
      selectBestMatch(
        null,
        [{ number: 3, state: 'open', title: 'agentcore' }],
        'agentcore',
      )?.number,
    ).toBe(3);
  });

  it('treats a candidate with NO title as a non-match (title ?? "")', () => {
    // Guards the `r.title ?? ''` branch: a numbered candidate with an absent
    // title cannot contain the needle, so it is filtered out.
    const match = selectBestMatch(
      [{ number: 50, state: 'open' } as { number: number }],
      [],
      'agentcore',
    );
    expect(match).toBeNull();
  });

  it('pulls a match out of the PRs list, not just issues', () => {
    const match = selectBestMatch(
      [],
      [{ number: 77, state: 'open', title: 'agentcore PR', url: 'x' }],
      'agentcore',
    );
    expect(match).toMatchObject({ number: 77 });
  });

  it('ignores candidates whose title does NOT mention the service', () => {
    // gh already searched, but selectBestMatch defensively requires a title
    // hit — a body-only hit (no title mention) must NOT be selected.
    const match = selectBestMatch(
      [{ number: 9, state: 'open', title: 'unrelated networking thing' }],
      [],
      'agentcore',
    );
    expect(match).toBeNull();
  });

  it('skips malformed candidates lacking a numeric number', () => {
    const match = selectBestMatch(
      [
        null as unknown as { number: number },
        { title: 'agentcore' } as unknown as { number: number },
        { number: 42, state: 'open', title: 'agentcore emulator' },
      ],
      [],
      'agentcore',
    );
    expect(match).toMatchObject({ number: 42 });
  });

  it('requires number to be a NUMBER, not merely present (typeof check)', () => {
    // Kills the `typeof r.number === 'number'` guard being dropped: a candidate
    // whose `number` is a STRING (and which title-matches) must be rejected —
    // dropping the typeof check would let it through as the sole match.
    const strung = selectBestMatch(
      [
        {
          number: '3' as unknown as number,
          state: 'open',
          title: 'agentcore strung',
        },
      ],
      [],
      'agentcore',
    );
    expect(strung).toBeNull();
  });

  it('prefers an OPEN issue over a CLOSED one, then the lowest number', () => {
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
    // #20: open + title contains the service name → best.
    expect(selectBestMatch(results, [], 'agentcore')?.number).toBe(20);
  });

  it('among equal OPEN title-hits breaks ties to the LOWEST number', () => {
    const results = [
      { number: 30, state: 'open', title: 'agentcore later' },
      { number: 12, state: 'open', title: 'agentcore earliest' },
    ];
    expect(selectBestMatch(results, [], 'agentcore')?.number).toBe(12);
  });

  it('OPEN beats CLOSED even when the CLOSED item has the LOWEST number', () => {
    // Designed to be sort-order-independent: a CLOSED #1 alongside OPEN #5/#9.
    // Correct comparator → open precedence wins, then lowest OPEN number (#5).
    // A broken open-precedence (the `a.open ? -1 : 1` sign) would fall back to
    // the number tie-break and pick the CLOSED #1 — a distinct, detectable
    // result. We assert BOTH the number and the state so neither sort branch
    // nor the state comparison can be mutated away undetected.
    const results = [
      { number: 1, state: 'closed', title: 'agentcore closed lowest' },
      { number: 9, state: 'open', title: 'agentcore open high' },
      { number: 5, state: 'open', title: 'agentcore open low' },
    ];
    const best = selectBestMatch(results, [], 'agentcore');
    expect(best?.number).toBe(5);
    expect(best?.state).toBe('open');
    // Reverse the array order too, to defeat any input-order dependence.
    const best2 = selectBestMatch([...results].reverse(), [], 'agentcore');
    expect(best2?.number).toBe(5);
    expect(best2?.state).toBe('open');
  });

  it('a CLOSED title-hit is still returned when it is the only match', () => {
    const results = [{ number: 8, state: 'closed', title: 'agentcore only' }];
    expect(selectBestMatch(results, [], 'agentcore')?.number).toBe(8);
  });

  it('drafts the EXACT structured comment body for a matched ref', () => {
    // Pin the whole body byte-for-byte so every template line (and the
    // matched-ref conditional + ETA ask branch) is mutation-covered.
    const digest =
      'sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';
    const body = draftCommentBody(
      {
        service: 'agentcore',
        status: 'upstream-tracked',
        ministackRef: 'ministackorg/ministack#1021',
      },
      digest,
    );
    expect(body).toBe(
      [
        `Hi from the [e2e-ministack](https://github.com/scottschreckengaust/e2e-ministack) compatibility harness 👋`,
        ``,
        `- **Service:** \`agentcore\``,
        `- **Our verdict:** \`upstream-tracked\``,
        `- **Verified against MiniStack digest:** \`${digest}\``,
        `- **Upstream ref:** ministackorg/ministack#1021`,
        ``,
        `**Ask:** Is there an ETA or a way we can help move agentcore forward? We track it against your issue ministackorg/ministack#1021.`,
        ``,
        `_This message was drafted by an automated harness but posted manually by a maintainer — replies are read by a human._`,
      ].join('\n'),
    );
  });

  it('drafts the EXACT NEW-issue-ask body when there is no ref yet (null branch)', () => {
    const body = draftCommentBody(
      { service: 'dsql', status: 'unsupported', ministackRef: null },
      '(unpinned)',
    );
    expect(body).toBe(
      [
        `Hi from the [e2e-ministack](https://github.com/scottschreckengaust/e2e-ministack) compatibility harness 👋`,
        ``,
        `- **Service:** \`dsql\``,
        `- **Our verdict:** \`unsupported\``,
        `- **Verified against MiniStack digest:** \`(unpinned)\``,
        `- **Upstream ref:** none found yet`,
        ``,
        `**Ask:** Would you consider tracking dsql emulation? We didn't find an existing issue/PR for it.`,
        ``,
        `_This message was drafted by an automated harness but posted manually by a maintainer — replies are read by a human._`,
      ].join('\n'),
    );
    expect(body).not.toContain('ETA');
  });

  it('builds the exact copy-pasteable post command for a known ref', () => {
    const cmd = formatPostCommand('ministackorg/ministack#1021', 'hello body');
    expect(cmd).toBe(
      "gh issue comment ministackorg/ministack#1021 --repo ministackorg/ministack --body 'hello body'",
    );
  });

  it('single-quote-escapes an apostrophe in the post command body', () => {
    const cmd = formatPostCommand('r#1', "it's here");
    // POSIX close-quote / escaped-quote / reopen: 'it'\''s here'
    expect(cmd).toContain(`--body 'it'\\''s here'`);
  });

  it('builds the issue URL for a ref, else the new-issue URL', () => {
    expect(formatOneClickUrl('ministackorg/ministack#1021')).toBe(
      `https://github.com/${UPSTREAM_REPO}/issues/1021`,
    );
    expect(formatOneClickUrl(null)).toBe(
      `https://github.com/${UPSTREAM_REPO}/issues/new`,
    );
  });

  it('validates a service name (rejects shell-metachar injection)', () => {
    // The service arg must never carry shell metacharacters into any execFile.
    expect(isValidServiceName('agentcore')).toBe(true);
    expect(isValidServiceName('rds-postgres')).toBe(true);
    expect(isValidServiceName('lambda')).toBe(true);
    expect(isValidServiceName('a; rm -rf /')).toBe(false);
    expect(isValidServiceName('$(whoami)')).toBe(false);
    expect(isValidServiceName('UPPER')).toBe(false); // lowercase only
    expect(isValidServiceName('-leading')).toBe(false);
    expect(isValidServiceName('trailing-')).toBe(false);
    expect(isValidServiceName('double--dash')).toBe(false);
    expect(isValidServiceName('')).toBe(false);
    expect(isValidServiceName(42)).toBe(false); // non-string
    expect(isValidServiceName(undefined)).toBe(false);
  });
});

describe('ministack-upstream.mjs — CLI contract', () => {
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
