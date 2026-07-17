import {
  MINISTACK_IMAGE,
  PIN_SITE_FILES,
  fanOut,
  formatReport,
  isValidDigest,
  substituteDigest,
} from '../../scripts/update-ministack';

// Unit tests for scripts/update-ministack.ts (#152). The PURE fan-out logic —
// validate a digest, substitute a pinned digest string, fan it across the pin
// sites, and format the report — lives in the `.ts` so it flows through the
// repo's 100% coverage gate (#124) + Stryker (#122). The network/IO half (the
// `docker buildx imagetools inspect` digest RESOLUTION, the file read/write,
// and running the drift guard to self-verify) lives in the un-gated
// `update-ministack.mjs` shim, mirroring `ministack-upstream.{ts,mjs}`.
//
// CORE INVARIANT: given old digest X present in N pin sites, produce contents
// carrying digest Y, touching ONLY the pinned-digest occurrences (never prose
// truncations or unrelated hex).

const OLD =
  'sha256:636c4ef52bff20e29f161d24e895359b2927f72a143d726792faa86160043ca9';
const NEW =
  'sha256:dd2cf4d2e58a9ee6534a52f1edf06a720064c24b90ca28d42b1c57181b9b8815';

describe('isValidDigest', () => {
  it('accepts a canonical sha256:<64-hex> digest', () => {
    expect(isValidDigest(OLD)).toBe(true);
    expect(isValidDigest(NEW)).toBe(true);
  });

  it('rejects a non-string', () => {
    expect(isValidDigest(undefined)).toBe(false);
    expect(isValidDigest(null)).toBe(false);
    expect(isValidDigest(123)).toBe(false);
    expect(isValidDigest({})).toBe(false);
  });

  it('rejects a wrong-length hex', () => {
    expect(isValidDigest('sha256:abc123')).toBe(false);
    expect(isValidDigest(`${OLD}ab`)).toBe(false);
  });

  it('rejects a missing sha256: prefix', () => {
    expect(
      isValidDigest(
        '636c4ef52bff20e29f161d24e895359b2927f72a143d726792faa86160043ca9',
      ),
    ).toBe(false);
  });

  it('rejects uppercase hex (digests are lowercase)', () => {
    expect(isValidDigest(OLD.toUpperCase())).toBe(false);
  });

  it('rejects a leading/trailing-decorated digest (anchored match)', () => {
    expect(isValidDigest(` ${OLD}`)).toBe(false);
    expect(isValidDigest(`${OLD} `)).toBe(false);
    expect(isValidDigest(`x${OLD}`)).toBe(false);
  });
});

describe('substituteDigest', () => {
  it('replaces every full pinned-digest occurrence and counts them', () => {
    const content = `run image@${OLD}\nother line\nagain @${OLD}\n`;
    const { content: out, replacements } = substituteDigest(content, OLD, NEW);
    expect(replacements).toBe(2);
    expect(out).toBe(`run image@${NEW}\nother line\nagain @${NEW}\n`);
    expect(out).not.toContain(OLD);
  });

  it('is a no-op (0 replacements) when the old digest is absent', () => {
    const content = 'nothing to see here\n';
    const { content: out, replacements } = substituteDigest(content, OLD, NEW);
    expect(replacements).toBe(0);
    expect(out).toBe(content);
  });

  it('leaves a truncated prose form untouched (only full 64-hex pins swap)', () => {
    // AGENTS.md-style prose uses a truncated `636c4ef5...`, never the full
    // digest — it must NOT be rewritten.
    const content = `see 636c4ef5… and also @${OLD}`;
    const { content: out, replacements } = substituteDigest(content, OLD, NEW);
    expect(replacements).toBe(1);
    expect(out).toBe(`see 636c4ef5… and also @${NEW}`);
    expect(out).toContain('636c4ef5…');
  });

  it('treats the old digest as a literal (no regex metachar surprises)', () => {
    // Defensive: a `.` in the search string must match a literal `.`, not any
    // char — split/join is literal, so a near-miss digest is NOT rewritten.
    const near = OLD.replace('636c', '636d');
    const content = `@${near}`;
    const { content: out, replacements } = substituteDigest(content, OLD, NEW);
    expect(replacements).toBe(0);
    expect(out).toBe(content);
  });

  it('is an exact no-op when old and new are identical (current-digest run)', () => {
    const content = `image@${OLD}\n`;
    const { content: out, replacements } = substituteDigest(content, OLD, OLD);
    expect(replacements).toBe(1);
    expect(out).toBe(content);
  });
});

describe('PIN_SITE_FILES', () => {
  it('is exactly the drift-guard site set (workflows + docs + registry)', () => {
    expect(PIN_SITE_FILES).toEqual([
      'services/_registry/ministack-pin.json',
      '.github/workflows/ci.yml',
      '.github/workflows/security.yml',
      '.github/workflows/ministack-compat.yml',
      'AGENTS.md',
      'README.md',
    ]);
  });

  it('excludes provisioning.json (semantic lastVerifiedDigest, not a blind pin)', () => {
    expect(PIN_SITE_FILES).not.toContain(
      'services/_registry/provisioning.json',
    );
  });

  it('names the canonical image', () => {
    expect(MINISTACK_IMAGE).toBe('ministackorg/ministack:full');
  });
});

describe('fanOut', () => {
  it('substitutes across every file and totals the replacements', () => {
    const files = [
      { path: 'a.yml', content: `x@${OLD}\n` },
      { path: 'b.md', content: `@${OLD} and @${OLD}\n` },
      { path: 'c.txt', content: 'unrelated\n' },
    ];
    const { results, total } = fanOut(files, OLD, NEW);
    expect(total).toBe(3);
    expect(results).toEqual([
      { path: 'a.yml', content: `x@${NEW}\n`, replacements: 1 },
      { path: 'b.md', content: `@${NEW} and @${NEW}\n`, replacements: 2 },
      { path: 'c.txt', content: 'unrelated\n', replacements: 0 },
    ]);
  });

  it('returns an empty result set and zero total for no files', () => {
    const { results, total } = fanOut([], OLD, NEW);
    expect(results).toEqual([]);
    expect(total).toBe(0);
  });
});

describe('formatReport', () => {
  it('lists the old→new digests, per-file counts, and the totals', () => {
    const results = [
      { path: 'a.yml', content: '', replacements: 1 },
      { path: 'b.md', content: '', replacements: 2 },
    ];
    const report = formatReport(results, OLD, NEW);
    expect(report).toContain(OLD);
    expect(report).toContain(NEW);
    expect(report).toContain('a.yml');
    expect(report).toContain('b.md');
    expect(report).toContain('3'); // total replacements
    expect(report).toContain('2'); // file count
  });

  it('flags a no-op run when old and new digests are identical', () => {
    const results = [{ path: 'a.yml', content: '', replacements: 1 }];
    const report = formatReport(results, OLD, OLD);
    expect(report).toMatch(/no change|already current|unchanged/i);
  });
});
