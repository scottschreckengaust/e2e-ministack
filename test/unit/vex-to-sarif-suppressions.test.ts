import {
  extractCve,
  collectSuppressions,
  injectSuppressions,
  type VexDoc,
  type SarifLogLike,
  type SarifResultLike,
} from '../../.github/scripts/vex-to-sarif-suppressions';

// Unit tests for .github/scripts/vex-to-sarif-suppressions.ts (issue #181):
// OpenVEX docs + a scanner SARIF -> SARIF with `suppressions[]` on VEX-covered
// results (kind:external) and `suppressions: []` on the rest (SARIF §3.27.23
// all-or-nothing). Imported IN-PROCESS so it flows through the 100% coverage
// gate (#124) + Stryker mutation (#122). Its output GATES the Code Scanning
// alert stream via advanced-security/dismiss-alerts, so correctness is
// security-relevant: a wrong suppression silently dismisses (or fails to
// re-open) a vulnerability alert.

// A VEX record shaped like the repo's .vex/CVE-*.openvex.json files.
const VEX_SQLITE: VexDoc = {
  statements: [
    {
      vulnerability: { name: 'CVE-2026-11822' },
      status: 'not_affected',
      justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
      impact_statement: 'Accepted risk: local-only CI emulator.',
    },
  ],
};

// A grype-style SARIF: rule id carries a package suffix (CVE-...-python).
function grypeSarif(ruleId: string): SarifLogLike {
  return {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'Grype', rules: [{ id: ruleId }] } },
        results: [
          {
            ruleId,
            level: 'error',
            message: { text: 'pkg vuln' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: 'image//usr/bin/x' },
                },
              },
            ],
          } as SarifResultLike,
        ],
      },
    ],
  };
}

describe('extractCve', () => {
  it('pulls a CVE from a grype package-suffixed rule id, upper-cased', () => {
    expect(extractCve('CVE-2026-0864-python')).toBe('CVE-2026-0864');
    expect(extractCve('cve-2026-0864-python')).toBe('CVE-2026-0864');
  });
  it('pulls a bare trivy CVE rule id', () => {
    expect(extractCve('CVE-2026-11822')).toBe('CVE-2026-11822');
  });
  it('returns null when no CVE token is present', () => {
    expect(extractCve('some-other-rule')).toBeNull();
    expect(extractCve('CVE-abc-123')).toBeNull(); // not the CVE-YYYY-N shape
  });
  it('returns null for non-string input (totality)', () => {
    expect(extractCve(undefined)).toBeNull();
    expect(extractCve(null)).toBeNull();
    expect(extractCve(42)).toBeNull();
    expect(extractCve({ ruleId: 'CVE-2026-1' })).toBeNull();
  });

  it('returns null for a NON-string that would coerce to a CVE-shaped string', () => {
    // Guards the `typeof value !== 'string'` clause specifically: a 1-element
    // array stringifies to its element, so without the type guard `.exec` would
    // coerce ['CVE-2026-1'] -> 'CVE-2026-1' and spuriously match. The guard must
    // reject it. (This kills the mutant that drops the typeof-string check.)
    expect(extractCve(['CVE-2026-0001'])).toBeNull();
  });
});

describe('collectSuppressions', () => {
  it('maps a not_affected CVE to a justification containing status + enum + impact', () => {
    const m = collectSuppressions([VEX_SQLITE]);
    expect(m.has('CVE-2026-11822')).toBe(true);
    const j = m.get('CVE-2026-11822')!;
    expect(j).toContain('not_affected');
    expect(j).toContain('vulnerable_code_cannot_be_controlled_by_adversary');
    expect(j).toContain('Accepted risk: local-only CI emulator.');
  });

  it('includes `fixed` status statements', () => {
    const m = collectSuppressions([
      {
        statements: [
          { vulnerability: { name: 'CVE-2026-1' }, status: 'fixed' },
        ],
      },
    ]);
    expect(m.has('CVE-2026-1')).toBe(true);
    expect(m.get('CVE-2026-1')).toContain('fixed');
  });

  it('EXCLUDES non-suppressing statuses (affected / under_investigation / missing)', () => {
    const m = collectSuppressions([
      {
        statements: [
          { vulnerability: { name: 'CVE-2026-2' }, status: 'affected' },
        ],
      },
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-3' },
            status: 'under_investigation',
          },
        ],
      },
      { statements: [{ vulnerability: { name: 'CVE-2026-4' } }] }, // no status
    ]);
    expect(m.size).toBe(0);
  });

  it('accepts a string-form vulnerability (not just {name})', () => {
    const m = collectSuppressions([
      { statements: [{ vulnerability: 'CVE-2026-5', status: 'not_affected' }] },
    ]);
    expect(m.has('CVE-2026-5')).toBe(true);
  });

  it('falls back to a default justification enum when justification is missing or empty', () => {
    const m = collectSuppressions([
      {
        statements: [
          { vulnerability: { name: 'CVE-2026-6' }, status: 'not_affected' },
        ],
      },
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-7' },
            status: 'not_affected',
            justification: '',
          },
        ],
      },
    ]);
    expect(m.get('CVE-2026-6')).toContain('vex_not_affected');
    expect(m.get('CVE-2026-7')).toContain('vex_not_affected');
  });

  it('omits the impact suffix when impact_statement is missing or empty', () => {
    const m = collectSuppressions([
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-8' },
            status: 'not_affected',
            justification: 'j',
          },
        ],
      },
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-9' },
            status: 'not_affected',
            justification: 'j',
            impact_statement: '',
          },
        ],
      },
    ]);
    // No trailing " — " separator when impact is absent/empty.
    expect(m.get('CVE-2026-8')).toBe('VEX not_affected (j)');
    expect(m.get('CVE-2026-9')).toBe('VEX not_affected (j)');
  });

  it('skips a statement whose vulnerability name has no CVE token', () => {
    const m = collectSuppressions([
      {
        statements: [
          { vulnerability: { name: 'GHSA-xxxx' }, status: 'not_affected' },
        ],
      },
    ]);
    expect(m.size).toBe(0);
  });

  it('last doc wins on a duplicate CVE', () => {
    const m = collectSuppressions([
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-10' },
            status: 'not_affected',
            justification: 'first',
          },
        ],
      },
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-10' },
            status: 'not_affected',
            justification: 'second',
          },
        ],
      },
    ]);
    expect(m.get('CVE-2026-10')).toContain('second');
    expect(m.get('CVE-2026-10')).not.toContain('first');
  });

  it('tolerates malformed inputs without throwing (totality)', () => {
    expect(collectSuppressions([]).size).toBe(0);
    expect(collectSuppressions(undefined as unknown as VexDoc[]).size).toBe(0);
    expect(collectSuppressions([{} as VexDoc]).size).toBe(0);
    expect(
      collectSuppressions([{ statements: undefined } as VexDoc]).size,
    ).toBe(0);
    expect(
      collectSuppressions([{ statements: 'x' } as unknown as VexDoc]).size,
    ).toBe(0);
    // a null statement element is skipped
    expect(
      collectSuppressions([{ statements: [null] } as unknown as VexDoc]).size,
    ).toBe(0);
    // vulnerability neither string nor object
    expect(
      collectSuppressions([
        {
          statements: [
            { vulnerability: 42 as unknown as string, status: 'not_affected' },
          ],
        },
      ]).size,
    ).toBe(0);
    // vulnerability is null (object-typed but falsy)
    expect(
      collectSuppressions([
        {
          statements: [
            {
              vulnerability: null as unknown as string,
              status: 'not_affected',
            },
          ],
        },
      ]).size,
    ).toBe(0);
  });
});

describe('injectSuppressions', () => {
  it('injects kind:external suppression on a covered grype result', () => {
    const { sarif, covered, uncoveredCves } = injectSuppressions(
      grypeSarif('CVE-2026-11822-sqlite'),
      [VEX_SQLITE],
    );
    const res = (
      sarif.runs as SarifResultLike[] as unknown as {
        results: SarifResultLike[];
      }[]
    )[0].results[0];
    expect(res.suppressions).toHaveLength(1);
    expect(res.suppressions![0].kind).toBe('external');
    expect(res.suppressions![0].justification).toContain('not_affected');
    expect(covered).toBe(1);
    expect(uncoveredCves).toEqual([]);
  });

  it('emits an EMPTY suppressions[] on an uncovered result and reports the CVE', () => {
    const { sarif, covered, uncoveredCves } = injectSuppressions(
      grypeSarif('CVE-2026-99999-nope'),
      [VEX_SQLITE],
    );
    const res = (sarif.runs as { results: SarifResultLike[] }[])[0].results[0];
    expect(res.suppressions).toEqual([]);
    expect(covered).toBe(0);
    expect(uncoveredCves).toEqual(['CVE-2026-99999']);
  });

  it('emits suppressions: [] on a result whose ruleId has no CVE (and does not report it as uncovered)', () => {
    const { sarif, uncoveredCves } = injectSuppressions(
      grypeSarif('lint-rule-x'),
      [VEX_SQLITE],
    );
    const res = (sarif.runs as { results: SarifResultLike[] }[])[0].results[0];
    expect(res.suppressions).toEqual([]);
    expect(uncoveredCves).toEqual([]);
  });

  it('does not mutate the caller input', () => {
    const input = grypeSarif('CVE-2026-11822-sqlite');
    injectSuppressions(input, [VEX_SQLITE]);
    const res = (input.runs as { results: SarifResultLike[] }[])[0].results[0];
    expect(res.suppressions).toBeUndefined();
  });

  it('dedupes uncovered CVEs across multiple results and sorts them', () => {
    const sarif: SarifLogLike = {
      version: '2.1.0',
      runs: [
        {
          results: [
            { ruleId: 'CVE-2026-3-a' },
            { ruleId: 'CVE-2026-1-b' },
            { ruleId: 'CVE-2026-3-c' }, // duplicate CVE-2026-3
          ] as SarifResultLike[],
        },
      ],
    };
    const { uncoveredCves } = injectSuppressions(sarif, []);
    expect(uncoveredCves).toEqual(['CVE-2026-1', 'CVE-2026-3']);
  });

  it('handles multiple runs (grype + a second run)', () => {
    const sarif: SarifLogLike = {
      version: '2.1.0',
      runs: [
        { results: [{ ruleId: 'CVE-2026-11822-x' }] as SarifResultLike[] },
        { results: [{ ruleId: 'CVE-2026-77777-y' }] as SarifResultLike[] },
      ],
    };
    const { covered, uncoveredCves } = injectSuppressions(sarif, [VEX_SQLITE]);
    expect(covered).toBe(1);
    expect(uncoveredCves).toEqual(['CVE-2026-77777']);
  });

  it('always emits a well-formed runs[] array, whatever the input (totality)', () => {
    // Missing / non-array / non-object / array inputs all normalize so the
    // OUTPUT is always an uploadable SARIF with runs: [].
    expect(injectSuppressions({} as SarifLogLike, []).sarif.runs).toEqual([]);
    expect(
      injectSuppressions({ runs: 'x' } as unknown as SarifLogLike, []).sarif
        .runs,
    ).toEqual([]);
    expect(
      injectSuppressions(null as unknown as SarifLogLike, []).sarif.runs,
    ).toEqual([]);
    expect(
      injectSuppressions(undefined as unknown as SarifLogLike, []).sarif.runs,
    ).toEqual([]);
    // A top-level ARRAY (not an object SARIF) is replaced, not cloned as runs.
    expect(
      injectSuppressions([1, 2, 3] as unknown as SarifLogLike, []).sarif.runs,
    ).toEqual([]);
    // run with no results array is passed through (covered stays 0)
    expect(
      injectSuppressions({ runs: [{ tool: {} }] } as SarifLogLike, []).covered,
    ).toBe(0);
    // null run element and non-array results element are skipped
    expect(
      injectSuppressions(
        { runs: [null, { results: 'nope' }] } as unknown as SarifLogLike,
        [],
      ).covered,
    ).toBe(0);
  });

  it('skips null/non-object result elements within a run', () => {
    const sarif = {
      runs: [{ results: [null, 7, { ruleId: 'CVE-2026-11822-z' }] }],
    } as unknown as SarifLogLike;
    const { covered } = injectSuppressions(sarif, [VEX_SQLITE]);
    expect(covered).toBe(1);
  });

  it('overwrites a pre-existing suppressions field (normalizes to VEX-derived / empty)', () => {
    const sarif = {
      runs: [
        {
          results: [
            {
              ruleId: 'CVE-2026-11822-a',
              suppressions: [{ kind: 'inSource', justification: 'stale' }],
            },
            {
              ruleId: 'CVE-2026-55555-b',
              suppressions: [{ kind: 'inSource', justification: 'stale' }],
            },
          ],
        },
      ],
    } as unknown as SarifLogLike;
    const { sarif: out } = injectSuppressions(sarif, [VEX_SQLITE]);
    const results = (out.runs as { results: SarifResultLike[] }[])[0].results;
    expect(results[0].suppressions).toEqual([
      {
        kind: 'external',
        justification: expect.stringContaining('not_affected'),
      },
    ]);
    expect(results[1].suppressions).toEqual([]); // stale inSource cleared
  });
});
