import {
  TOKENS,
  isDocPath,
  isSelfPath,
  isVexRecord,
  isTestPath,
  isBacktickQuoted,
  isCommentLine,
  classifyHit,
  scanLine,
  buildReport,
  toSarif,
  formatText,
  type TokenDef,
} from '../../.github/scripts/suppression-inventory';

// Unit tests for .github/scripts/suppression-inventory.ts (#202): the pure
// suppression-token catalog + 3-bucket classifier + report/SARIF builders.
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124) +
// Stryker mutation (#122). The runnable CLI is the thin
// suppression-inventory.mjs shim (ripgrep walk + read/write/exit), not covered
// here (it's the .mjs I/O plumbing, excluded by the .ts-only coverage globs).

const tok = (over: Partial<TokenDef> = {}): TokenDef => ({
  id: 'x',
  tool: 'X',
  pattern: 'nosemgrep',
  kind: 'comment',
  note: 'n',
  ...over,
});

describe('suppression-inventory — catalog', () => {
  it('every token has a unique id, a compilable pattern, and a note', () => {
    const ids = new Set<string>();
    for (const t of TOKENS) {
      expect(t.id).toBeTruthy();
      expect(ids.has(t.id)).toBe(false);
      ids.add(t.id);
      expect(() => new RegExp(t.pattern)).not.toThrow();
      expect(t.note).toBeTruthy();
      expect(['comment', 'config']).toContain(t.kind);
    }
  });

  it('includes the priority in-repo tokens from the #202 catalog', () => {
    const ids = TOKENS.map((t) => t.id);
    for (const id of [
      'semgrep-nosemgrep',
      'semgrep-exclude-rule',
      'checkov-metadata-skip',
      'cdknag-acknowledge',
      'eslint-disable',
      'stryker-disable',
      'gitleaks-allowlist',
      'grype-vex-documents',
      'trivy-vex',
      'depreview-allow-licenses',
    ]) {
      expect(ids).toContain(id);
    }
  });
});

describe('suppression-inventory — path/line predicates', () => {
  it('isDocPath: docs/ or *.md are documentation', () => {
    expect(isDocPath('docs/SECURITY-TOOLING.md')).toBe(true);
    expect(isDocPath('README.md')).toBe(true);
    expect(isDocPath('lib/stack.ts')).toBe(false);
    expect(isDocPath('.github/workflows/security.yml')).toBe(false);
  });

  it('isSelfPath: the inventory tooling names the catalog as data', () => {
    expect(isSelfPath('.github/scripts/suppression-inventory.ts')).toBe(true);
    expect(isSelfPath('.github/scripts/suppression-inventory.mjs')).toBe(true);
    expect(isSelfPath('lib/stack.ts')).toBe(false);
  });

  it('isVexRecord: only .vex/*.openvex.json', () => {
    expect(isVexRecord('.vex/CVE-2026-1525.openvex.json')).toBe(true);
    expect(isVexRecord('.vex/ecdsa-CVE-2024-23342.openvex.json')).toBe(true);
    expect(isVexRecord('.vex/README.md')).toBe(false);
    expect(isVexRecord('trivy.yaml')).toBe(false);
  });

  it('isTestPath: the test/ tree or a *.test.* / *.spec.* filename', () => {
    expect(isTestPath('test/unit/vex-dialects.test.ts')).toBe(true);
    expect(isTestPath('test/setup.fast-check.ts')).toBe(true);
    // specs that live OUTSIDE test/ are caught by the filename signal
    expect(isTestPath('services/lambda/invoke.test.ts')).toBe(true);
    expect(isTestPath('fuzz/handler.regression.test.js')).toBe(true);
    // the real config SURFACES must never be test paths
    expect(isTestPath('osv-scanner.toml')).toBe(false);
    expect(isTestPath('trivy.yaml')).toBe(false);
    expect(isTestPath('.github/workflows/ci.yml')).toBe(false);
    expect(isTestPath('.gitleaks.toml')).toBe(false);
    expect(isTestPath('lib/ministack-stack.ts')).toBe(false);
    // a `test` substring elsewhere in the path is not a test tree
    expect(isTestPath('lib/latest/thing.ts')).toBe(false);
    expect(isTestPath('src/protest.ts')).toBe(false);
  });

  it.each([
    'a.test.ts',
    'a.test.js',
    'a.test.mjs',
    'a.test.cjs',
    'a.test.tsx',
    'a.test.jsx',
    'a.spec.ts',
    'a.spec.js',
    'a.spec.mjs',
    'a.spec.cjs',
    'a.spec.tsx',
    'a.spec.jsx',
  ])('isTestPath: recognizes the spec filename %s', (p) => {
    expect(isTestPath(p)).toBe(true);
  });

  it.each([
    'a.test.toml', // not a JS/TS extension
    'a.tests.ts', // not the `.test.` segment
    'a.specs.ts',
    'atest.ts', // no dot before `test`
    'a.test.ts.bak', // spec segment not at end of path
    'a.ts',
  ])('isTestPath: does NOT recognize %s', (p) => {
    expect(isTestPath(p)).toBe(false);
  });

  it('isCommentLine: recognizes #, //, /*, *, <!-- leaders', () => {
    expect(isCommentLine('  # a comment')).toBe(true);
    expect(isCommentLine('// a comment')).toBe(true);
    expect(isCommentLine('/* a comment */')).toBe(true);
    expect(isCommentLine(' * jsdoc line')).toBe(true);
    expect(isCommentLine('<!-- md comment -->')).toBe(true);
    expect(isCommentLine('  allow-dependencies-licenses: x')).toBe(false);
  });
});

describe('suppression-inventory — isBacktickQuoted', () => {
  const re = /nosemgrep/i;
  it('true when the token is inside a closed backtick pair', () => {
    expect(isBacktickQuoted('rather than `# nosemgrep` here', re)).toBe(true);
  });
  it('false when the token is outside backticks', () => {
    expect(isBacktickQuoted('use nosemgrep here `elsewhere`', re)).toBe(false);
  });
  it('false with no backticks at all', () => {
    expect(isBacktickQuoted('plain nosemgrep line', re)).toBe(false);
  });
  it('unbalanced trailing backtick segment is NOT treated as quoted', () => {
    // odd backtick count: the open trailing segment must not exempt the token
    expect(isBacktickQuoted('open `code nosemgrep', re)).toBe(false);
  });
  it('handles multiple backtick pairs (even count)', () => {
    expect(isBacktickQuoted('`a` and `nosemgrep`', re)).toBe(true);
    expect(isBacktickQuoted('`a` plain `b` nosemgrep', re)).toBe(false);
  });
});

describe('suppression-inventory — classifyHit (all buckets)', () => {
  const re = /nosemgrep/i;
  it('1: documentation prose → wiring', () => {
    const c = classifyHit({
      path: 'docs/x.md',
      text: 'we use nosemgrep',
      token: tok(),
      re,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/documentation/);
  });

  it('2: self-reference tooling → wiring', () => {
    const c = classifyHit({
      path: '.github/scripts/suppression-inventory.ts',
      text: 'nosemgrep',
      token: tok(),
      re,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/self-reference/);
  });

  it('3: backtick-quoted mention → wiring', () => {
    const c = classifyHit({
      path: '.github/workflows/security.yml',
      text: 'rather than `# nosemgrep`',
      token: tok(),
      re,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/backtick/);
  });

  it('4: .vex/ OpenVEX record → registered', () => {
    const c = classifyHit({
      path: '.vex/CVE-2026-1525.openvex.json',
      text: '"status": "not_affected"',
      token: tok({ id: 'anything', pattern: 'not_affected' }),
      re: /not_affected/,
    });
    expect(c.bucket).toBe('registered');
    expect(c.reason).toMatch(/OpenVEX/);
  });

  it('5: config directive named in a comment → wiring (not registered)', () => {
    const c = classifyHit({
      path: '.github/workflows/security.yml',
      text: '# allow-dependencies-licenses carries two entries',
      token: tok({
        id: 'depreview-allow-licenses',
        pattern: 'allow-dependencies-licenses',
        kind: 'config',
        registered: true,
      }),
      re: /allow-dependencies-licenses/,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/comment/);
  });

  it('6: config directive in a test spec → wiring (spec is not a config surface)', () => {
    // The false positive this rule exists for: test/unit/vex-dialects.test.ts
    // asserts on the FORMAT of the generated osv-scanner.toml ignore block, so
    // the literal must appear in the spec. A spec is not a config surface.
    const c = classifyHit({
      path: 'test/unit/vex-dialects.test.ts',
      text: "    expect(toml).toContain('[[IgnoredVulns]]');",
      token: tok({
        id: 'osv-ignored-vulns',
        pattern: '\\[\\[IgnoredVulns\\]\\]',
        kind: 'config',
      }),
      re: /\[\[IgnoredVulns\]\]/,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/test spec/);
  });

  it('6: a BARE config token in a spec fixture (no quotes at all) → wiring', () => {
    // A continuation line inside a multi-line template-literal golden fixture:
    // no backticks/quotes on the line, so only the SURFACE argument covers it.
    const c = classifyHit({
      path: 'test/unit/vex-dialects.test.ts',
      text: '[[IgnoredVulns]]',
      token: tok({
        id: 'osv-ignored-vulns',
        pattern: '\\[\\[IgnoredVulns\\]\\]',
        kind: 'config',
      }),
      re: /\[\[IgnoredVulns\]\]/,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/test spec/);
  });

  it('6 is NOT "path is a test ⇒ exempt": a REAL comment-kind suppression directive in a test file stays raw', () => {
    // THE SAFETY TEST for rule 6. The test-spec exemption is scoped to
    // `config`-kind tokens; a `comment`-kind token IS the suppression wherever
    // it lives, so every inline directive in the catalog must still be flagged
    // inside test/**. If this ever goes green as `wiring`, rule 6 has become a
    // hole in the detector.
    const inlineDirectives: Array<[string, string, string, RegExp]> = [
      [
        'eslint-disable',
        'eslint-disable',
        '  // eslint-disable-next-line no-console',
        /eslint-disable/,
      ],
      ['semgrep-nosemgrep', 'nosemgrep', '  // nosemgrep', /nosemgrep/],
      [
        'istanbul-ignore',
        'istanbul\\s+ignore',
        '  /* istanbul ignore next */',
        /istanbul\s+ignore/,
      ],
      [
        'stryker-disable',
        'Stryker\\s+(disable|restore)',
        '  // Stryker disable next-line all',
        /Stryker\s+(disable|restore)/,
      ],
      [
        'ts-expect-error',
        '@ts-expect-error',
        '  // @ts-expect-error probing a bad call',
        /@ts-expect-error/,
      ],
      [
        'checkov-inline-skip',
        'checkov:skip=',
        '  # checkov:skip=CKV_AWS_18',
        /checkov:skip=/,
      ],
    ];
    for (const [id, pattern, text, re] of inlineDirectives) {
      const c = classifyHit({
        path: 'test/unit/some.test.ts',
        text,
        token: tok({ id, pattern, kind: 'comment' }),
        re,
      });
      expect({ id, bucket: c.bucket }).toEqual({ id, bucket: 'raw' });
    }
  });

  it('6 does not exempt a config directive on a REAL config surface', () => {
    // The live, generated osv-scanner.toml block stays raw — the gate must not
    // get quieter anywhere outside a spec file.
    const c = classifyHit({
      path: 'osv-scanner.toml',
      text: '[[IgnoredVulns]]',
      token: tok({
        id: 'osv-ignored-vulns',
        pattern: '\\[\\[IgnoredVulns\\]\\]',
        kind: 'config',
      }),
      re: /\[\[IgnoredVulns\]\]/,
    });
    expect(c.bucket).toBe('raw');
  });

  it('7: active registered config directive → registered', () => {
    const c = classifyHit({
      path: '.github/workflows/security.yml',
      text: "allow-dependencies-licenses: 'pkg:...'",
      token: tok({
        id: 'depreview-allow-licenses',
        pattern: 'allow-dependencies-licenses',
        kind: 'config',
        registered: true,
      }),
      re: /allow-dependencies-licenses/,
    });
    expect(c.bucket).toBe('registered');
    expect(c.reason).toMatch(/migrate → #167/);
  });

  it('8: active VEX feed directive → wiring', () => {
    const c = classifyHit({
      path: '.github/workflows/security.yml',
      text: 'GRYPE_VEX_DOCUMENTS: ${{ steps.vex.outputs.docs }}',
      token: tok({
        id: 'grype-vex-documents',
        pattern: 'GRYPE_VEX_DOCUMENTS',
        kind: 'config',
        vexFeed: true,
      }),
      re: /GRYPE_VEX_DOCUMENTS/,
    });
    expect(c.bucket).toBe('wiring');
    expect(c.reason).toMatch(/VEX feed/);
  });

  it('9: bare in-code suppression → raw', () => {
    const c = classifyHit({
      path: '.github/workflows/security.yml',
      text: '# shellcheck disable=SC2086',
      token: tok({
        id: 'shellcheck-disable',
        pattern: 'shellcheck\\s+disable',
        kind: 'comment',
      }),
      re: /shellcheck\s+disable/,
    });
    expect(c.bucket).toBe('raw');
    expect(c.reason).toMatch(/#202 target/);
  });

  it('a comment-kind token quoted in a comment is still raw when active', () => {
    // A `config` mention in a comment is wiring (rule 5), but a `comment`-kind
    // token that IS the directive must NOT get that exemption.
    const c = classifyHit({
      path: 'src/x.ts',
      text: '// eslint-disable-next-line no-console',
      token: tok({
        id: 'eslint-disable',
        pattern: 'eslint-disable',
        kind: 'comment',
      }),
      re: /eslint-disable/,
    });
    expect(c.bucket).toBe('raw');
  });
});

describe('suppression-inventory — scanLine', () => {
  it('classifies each matching token on the line', () => {
    const hits = scanLine('src/x.ts', 7, '// eslint-disable-next-line');
    expect(hits).toHaveLength(1);
    expect(hits[0]).toMatchObject({
      path: 'src/x.ts',
      line: 7,
      tokenId: 'eslint-disable',
      tool: 'ESLint',
      bucket: 'raw',
    });
    expect(hits[0].text).toBe('// eslint-disable-next-line');
  });

  it('matches case-insensitive tokens (NOSONAR)', () => {
    const hits = scanLine('src/x.java', 1, 'doThing(); // nosonar');
    expect(hits.map((h) => h.tokenId)).toContain('nosonar');
  });

  it('returns [] for a line with no token', () => {
    expect(scanLine('src/x.ts', 1, 'const a = 1;')).toEqual([]);
  });

  it('can return multiple hits for one line', () => {
    const hits = scanLine('src/x.ts', 1, 'nosemgrep and eslint-disable here');
    expect(hits.map((h) => h.tokenId).sort()).toEqual(
      ['eslint-disable', 'semgrep-nosemgrep'].sort(),
    );
  });
});

describe('suppression-inventory — buildReport', () => {
  it('buckets hits and carries the vex-record count', () => {
    const hits = [
      ...scanLine('src/a.ts', 1, '// eslint-disable'), // raw
      ...scanLine('docs/a.md', 1, 'nosemgrep'), // wiring
      ...scanLine('.gitleaks.toml', 1, '[[allowlists]]'), // registered
    ];
    const r = buildReport(hits, 59);
    expect(r.total).toBe(3);
    expect(r.counts).toEqual({ raw: 1, registered: 1, wiring: 1 });
    expect(r.raw).toHaveLength(1);
    expect(r.registered).toHaveLength(1);
    expect(r.wiring).toHaveLength(1);
    expect(r.vexRecords).toBe(59);
  });

  it('empty input yields an all-zero report', () => {
    const r = buildReport([], 0);
    expect(r.total).toBe(0);
    expect(r.counts).toEqual({ raw: 0, registered: 0, wiring: 0 });
  });
});

describe('suppression-inventory — toSarif', () => {
  it('emits one warning-level result per raw hit', () => {
    const hits = scanLine('src/a.ts', 3, '// eslint-disable');
    const sarif = toSarif(hits);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.$schema).toContain('sarif-schema-2.1.0.json');
    expect(sarif.runs[0].tool.driver.name).toBe('suppression-inventory');
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
    expect(sarif.runs[0].results).toHaveLength(1);
    const res = sarif.runs[0].results[0];
    expect(res.ruleId).toBe('eslint-disable');
    expect(res.level).toBe('warning');
    expect(res.properties['security-severity']).toBe('4.0');
    expect(res.message.text).toContain('Unregistered ESLint suppression');
    expect(res.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'src/a.ts',
    );
    expect(res.locations[0].physicalLocation.region.startLine).toBe(3);
  });

  it('empty raw list yields a valid empty-results SARIF', () => {
    const sarif = toSarif([]);
    expect(sarif.runs[0].results).toEqual([]);
  });
});

describe('suppression-inventory — formatText', () => {
  it('renders the counts header and one line per hit', () => {
    const hits = [
      ...scanLine('src/a.ts', 1, '// eslint-disable'),
      ...scanLine('.gitleaks.toml', 2, '[[allowlists]]'),
      ...scanLine('docs/a.md', 3, 'nosemgrep'),
    ];
    const text = formatText(buildReport(hits, 59));
    expect(text).toContain('REPORT-ONLY');
    expect(text).toContain('raw (unregistered — target): 1');
    expect(text).toContain('registered (reason-bearing → #167): 1');
    expect(text).toContain('wiring (feed config / docs — ignore): 1');
    expect(text).toContain('.vex/ OpenVEX records (registered): 59');
    expect(text).toContain('src/a.ts:1');
    expect(text).toContain('── RAW (1) ──');
    expect(text).toContain('── REGISTERED (1) ──');
    expect(text).toContain('── WIRING (1) ──');
  });
});
