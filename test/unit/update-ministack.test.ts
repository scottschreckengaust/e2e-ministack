import {
  BIN_DIRS,
  MINISTACK_IMAGE,
  PIN_SITE_FILES,
  fanOut,
  formatReport,
  isValidDigest,
  resolveBin,
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

  it('rejects a NON-string whose toString would match the pattern', () => {
    // A single-element array String()-coerces to its element's text, so
    // `String([digest]) === digest`. `.test()` coerces its arg, so if the
    // `typeof === 'string'` guard were dropped this array would slip through.
    // Asserting FALSE here kills the ConditionalExpression→true mutant on the
    // typeof guard (which a plain `{}`/number can't, since those coerce to a
    // non-matching string and fail the regex anyway).
    expect(isValidDigest([OLD])).toBe(false);
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
  it('renders the EXACT report: header, per-file counts, and totals', () => {
    // Full-string equality (not toContain) pins every line and its ordering, so
    // a blanked literal, a run-together `join('')`, a dropped no-op guard, or a
    // corrupted `total` reduce all change the string and are killed.
    const results = [
      { path: 'a.yml', content: '', replacements: 1 },
      { path: 'b.md', content: '', replacements: 2 },
    ];
    const report = formatReport(results, OLD, NEW);
    expect(report).toBe(
      [
        `MiniStack image: ${MINISTACK_IMAGE}`,
        `  old: ${OLD}`,
        `  new: ${NEW}`,
        '',
        'Pin sites (2 files):',
        '  1x  a.yml',
        '  2x  b.md',
        '',
        'Total replacements: 3 across 2 files',
      ].join('\n'),
    );
  });

  it('computes total by SUMMING (not subtracting) the per-file counts', () => {
    // A single positive total that cannot be produced by `sum - r` (which would
    // go negative), so the ArithmeticOperator mutant on the reduce is killed —
    // the `-3` a subtraction yields still "contains 3", so only an exact number
    // check distinguishes them.
    const results = [
      { path: 'a.yml', content: '', replacements: 2 },
      { path: 'b.md', content: '', replacements: 3 },
    ];
    expect(formatReport(results, OLD, NEW)).toContain(
      'Total replacements: 5 across 2 files',
    );
  });

  it('reports a zero total (not undefined) when nothing was replaced', () => {
    // Kills the ArrowFunction mutant that replaces the reduce callback with
    // `() => undefined`: the seed is 0, so a no-op callback would surface
    // `undefined` here rather than 0.
    const results = [{ path: 'a.yml', content: '', replacements: 0 }];
    expect(formatReport(results, OLD, NEW)).toContain(
      'Total replacements: 0 across 1 files',
    );
  });

  it('flags a no-op run when old and new digests are identical (EXACT)', () => {
    const results = [{ path: 'a.yml', content: '', replacements: 1 }];
    const report = formatReport(results, OLD, OLD);
    expect(report).toBe(
      [
        `MiniStack image: ${MINISTACK_IMAGE}`,
        `  old: ${OLD}`,
        `  new: ${OLD}`,
        '  (no change — pin already current; fan-out is a no-op)',
        '',
        'Pin sites (1 files):',
        '  1x  a.yml',
        '',
        'Total replacements: 1 across 1 files',
      ].join('\n'),
    );
  });

  it('omits the no-op line when old and new digests differ', () => {
    // The complement of the guard: with distinct digests the "(no change …)"
    // line must be ABSENT. Kills the ConditionalExpression→true mutant that
    // would always push it.
    const report = formatReport(
      [{ path: 'a.yml', content: '', replacements: 1 }],
      OLD,
      NEW,
    );
    expect(report).not.toContain('no change');
  });
});

describe('resolveBin (S4036: never consult $PATH)', () => {
  // A fake fileExists over a controlled set of "present" absolute paths.
  const existsIn = (present: string[]) => (p: string) => present.includes(p);

  it('honors an ABSOLUTE, existing override before the allow-list', () => {
    const seen: string[] = [];
    const fileExists = (p: string) => {
      seen.push(p);
      return p === '/opt/custom/docker';
    };
    expect(resolveBin('docker', '/opt/custom/docker', fileExists)).toBe(
      '/opt/custom/docker',
    );
    // The override is checked FIRST and short-circuits — the allow-list dirs
    // are never probed once it matches.
    expect(seen).toEqual(['/opt/custom/docker']);
  });

  it('REJECTS a bare-name override EVEN WHEN it "exists" (no $PATH/cwd trust)', () => {
    // fileExists returns TRUE for the bare `docker` too. The real code still
    // rejects it (fails the `startsWith('/')` absolute check) and falls through
    // to the allow-list. Kills the mutant that weakens the absolute guard to
    // `startsWith('')` (always true), which would accept the bare name and
    // re-introduce a $PATH/cwd lookup.
    const found = resolveBin(
      'docker',
      'docker',
      existsIn(['docker', '/usr/bin/docker']),
    );
    expect(found).toBe('/usr/bin/docker');
  });

  it('REJECTS a relative-path override EVEN WHEN it "exists" (cwd-plantable)', () => {
    const found = resolveBin(
      'docker',
      './docker',
      existsIn(['./docker', '/usr/local/bin/docker']),
    );
    expect(found).toBe('/usr/local/bin/docker');
  });

  it('REJECTS an absolute override that does NOT exist (falls through)', () => {
    const found = resolveBin(
      'docker',
      '/nope/docker',
      existsIn(['/usr/bin/docker']),
    );
    expect(found).toBe('/usr/bin/docker');
  });

  it('ignores an undefined override and uses the allow-list', () => {
    const found = resolveBin('bash', undefined, existsIn(['/usr/bin/bash']));
    expect(found).toBe('/usr/bin/bash');
  });

  it('falls back to the first existing allow-list dir, in order', () => {
    // Present in BOTH the 4th and 5th dirs — must return the EARLIER one,
    // proving order is honored (kills a loop-order / array-reversal mutant).
    const found = resolveBin(
      'docker',
      undefined,
      existsIn([
        '/opt/homebrew/bin/docker',
        '/home/linuxbrew/.linuxbrew/bin/docker',
      ]),
    );
    expect(found).toBe('/opt/homebrew/bin/docker');
  });

  it('resolves from the POSIX /bin dir when it is the only one', () => {
    const found = resolveBin('bash', undefined, existsIn(['/bin/bash']));
    expect(found).toBe('/bin/bash');
  });

  it('appends /<name> to each allow-list dir (probes the exact expected paths)', () => {
    const seen: string[] = [];
    expect(() =>
      resolveBin('docker', undefined, (p) => {
        seen.push(p);
        return false;
      }),
    ).toThrow();
    expect(seen).toEqual(BIN_DIRS.map((d) => `${d}/docker`));
  });

  it('throws a clear, actionable error when the binary is nowhere', () => {
    expect(() => resolveBin('docker', undefined, () => false)).toThrow(
      /docker not found/,
    );
    // The message names the escape hatch so the operator knows the fix.
    expect(() => resolveBin('docker', undefined, () => false)).toThrow(
      /override/,
    );
    // It lists the probed dirs COMMA-separated (kills the `.join('')` mutant
    // that would run the dir names together into an unreadable blob).
    expect(() => resolveBin('docker', undefined, () => false)).toThrow(
      '/usr/bin, /usr/local/bin',
    );
  });

  it('interpolates the requested name into the error (not a literal)', () => {
    // Kills a mutant that replaces the `${name}` interpolation with a literal
    // by proving the SAME function reports different names.
    expect(() => resolveBin('bash', undefined, () => false)).toThrow(
      /bash not found/,
    );
  });

  it('exposes the expected fixed allow-list (no $PATH-derived entries)', () => {
    expect(BIN_DIRS).toEqual([
      '/usr/bin',
      '/usr/local/bin',
      '/bin',
      '/opt/homebrew/bin',
      '/home/linuxbrew/.linuxbrew/bin',
    ]);
    // Every entry is an absolute, fixed path.
    for (const d of BIN_DIRS) expect(d.startsWith('/')).toBe(true);
  });
});
