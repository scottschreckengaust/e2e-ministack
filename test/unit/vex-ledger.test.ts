import {
  asArray,
  asRecord,
  normId,
  statementIds,
  revisitDate,
  isRevisitOverdue,
  recordIds,
  activeRecordIds,
} from '../../.github/scripts/vex-ledger';

// Unit tests for .github/scripts/vex-ledger.ts (issue #295): the SHARED VEX
// ledger core. Extracts the identifier-matching that was independently
// re-implemented across grype-fs-gate.ts (CVE∪GHSA union) and the dialect
// generators (CVE-only regex) into ONE matcher, so every scanner surface
// (grype FS, trivy, OSV, SARIF, and the new npm-audit gate) agrees on which
// ids a `.vex/` record accepts. Adds the dated-`revisit_by` EXPIRY mechanism
// (the `.nsprc`-parity self-expiry decided on #295): an acceptance whose
// record carries a dated `revisit_by` on/before today stops covering, so the
// finding re-reds automatically instead of rotting silently.
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124),
// Stryker mutation (#122), and the fuzz-regression tier's totality guarantee.

// -- small total coercions (identical contract to grype-fs-gate's copies; this
//    module is where they consolidate) --
describe('asArray', () => {
  it('returns arrays unchanged and coerces non-arrays to []', () => {
    expect(asArray([1, 2])).toEqual([1, 2]);
    expect(asArray(null)).toEqual([]);
    expect(asArray(undefined)).toEqual([]);
    expect(asArray('x')).toEqual([]);
    expect(asArray({})).toEqual([]);
  });
});

describe('asRecord', () => {
  it('accepts plain objects, rejects arrays and primitives', () => {
    expect(asRecord({ a: 1 })).toEqual({ a: 1 });
    expect(asRecord([])).toBeNull();
    expect(asRecord(null)).toBeNull();
    expect(asRecord('x')).toBeNull();
    expect(asRecord(3)).toBeNull();
  });
});

describe('normId', () => {
  it('upper-cases and trims a string id', () => {
    expect(normId('cve-2026-13149')).toBe('CVE-2026-13149');
    expect(normId('  ghsa-3jxr-9vmj-r5cp  ')).toBe('GHSA-3JXR-9VMJ-R5CP');
  });
  it('returns null for non-strings and empty/whitespace', () => {
    expect(normId(null)).toBeNull();
    expect(normId(123)).toBeNull();
    expect(normId('')).toBeNull();
    expect(normId('   ')).toBeNull();
    expect(normId(['CVE-2026-13149'])).toBeNull();
  });
});

describe('statementIds', () => {
  it('collects the normalized name AND every alias of one statement', () => {
    expect(
      statementIds({
        vulnerability: {
          name: 'cve-2026-13149',
          aliases: ['GHSA-3jxr-9vmj-r5cp'],
        },
        status: 'affected',
      }),
    ).toEqual(['CVE-2026-13149', 'GHSA-3JXR-9VMJ-R5CP']);
  });
  it('yields the name alone when aliases are absent', () => {
    expect(statementIds({ vulnerability: { name: 'CVE-2005-2541' } })).toEqual([
      'CVE-2005-2541',
    ]);
  });
  it('skips a missing/blank name but keeps usable aliases', () => {
    expect(
      statementIds({ vulnerability: { aliases: ['GHSA-aaaa-bbbb-cccc', ''] } }),
    ).toEqual(['GHSA-AAAA-BBBB-CCCC']);
  });
  it('returns [] for a non-record statement or missing vulnerability', () => {
    expect(statementIds('nope')).toEqual([]);
    expect(statementIds(42)).toEqual([]);
    expect(statementIds(null)).toEqual([]);
    expect(statementIds({})).toEqual([]);
    expect(statementIds({ vulnerability: 'nope' })).toEqual([]);
  });
  it('tolerates a non-array aliases field', () => {
    expect(
      statementIds({ vulnerability: { name: 'CVE-2026-1', aliases: 7 } }),
    ).toEqual(['CVE-2026-1']);
  });
});

describe('revisitDate', () => {
  it('extracts a UTC Date when the string embeds an ISO calendar date', () => {
    const d = revisitDate('revisit 2026-10-01');
    expect(d).toBeInstanceOf(Date);
    expect(d?.toISOString()).toBe('2026-10-01T00:00:00.000Z');
  });
  it('returns undefined for the event-token vocabulary (no date)', () => {
    expect(revisitDate('wait-for-image-rebuild')).toBeUndefined();
    expect(
      revisitDate('waiting-on-upstream-issue https://x/1'),
    ).toBeUndefined();
  });
  it('returns undefined for non-strings', () => {
    expect(revisitDate(undefined)).toBeUndefined();
    expect(revisitDate(null)).toBeUndefined();
    expect(revisitDate(20261001)).toBeUndefined();
  });
  it('returns undefined for a structurally-ISO but invalid calendar date', () => {
    // matches the regex but `new Date` yields Invalid Date
    expect(revisitDate('2026-13-45')).toBeUndefined();
  });
});

describe('isRevisitOverdue', () => {
  const today = new Date('2026-07-22T12:00:00.000Z');
  it('is true when a dated revisit_by is strictly before today', () => {
    expect(isRevisitOverdue('revisit 2026-01-01', today)).toBe(true);
  });
  it('is true when a dated revisit_by falls on today (on/before)', () => {
    // 2026-07-22T00:00Z <= 2026-07-22T12:00Z
    expect(isRevisitOverdue('2026-07-22', today)).toBe(true);
  });
  it('is true at the exact instant (revisit == now) — the <= boundary', () => {
    // revisit_by parses to UTC midnight; comparing at the SAME instant proves
    // the comparison is `<=` not `<` (an overdue-on-the-dot record must expire).
    const midnight = new Date('2026-07-22T00:00:00.000Z');
    expect(isRevisitOverdue('2026-07-22', midnight)).toBe(true);
  });
  it('is false when a dated revisit_by is in the future', () => {
    expect(isRevisitOverdue('2026-10-01', today)).toBe(false);
  });
  it('is false for the event-token vocabulary (never expires)', () => {
    expect(isRevisitOverdue('wait-for-image-rebuild', today)).toBe(false);
  });
  it('is false for non-strings and an invalid date', () => {
    expect(isRevisitOverdue(undefined, today)).toBe(false);
    expect(isRevisitOverdue('2026-13-45', today)).toBe(false);
  });
});

describe('recordIds', () => {
  function doc(
    name: string,
    aliases: string[],
    extra: Record<string, unknown> = {},
  ): unknown {
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [{ vulnerability: { name, aliases }, status: 'affected' }],
      ...extra,
    };
  }

  it('unions the name AND aliases of every statement across all docs', () => {
    const ids = recordIds([
      doc('CVE-2026-13149', ['GHSA-3jxr-9vmj-r5cp']),
      doc('CVE-2005-2541', []),
    ]);
    expect(ids.has('CVE-2026-13149')).toBe(true);
    expect(ids.has('GHSA-3JXR-9VMJ-R5CP')).toBe(true);
    expect(ids.has('CVE-2005-2541')).toBe(true);
    expect(ids.size).toBe(3);
  });
  it('accepts BOTH affected and not_affected records (no status filter)', () => {
    const ids = recordIds([
      doc('CVE-2026-13149', [], { statements: undefined }),
      {
        statements: [
          { vulnerability: { name: 'CVE-1' }, status: 'not_affected' },
          { vulnerability: { name: 'CVE-2' }, status: 'affected' },
        ],
      },
    ]);
    expect(ids.has('CVE-1')).toBe(true);
    expect(ids.has('CVE-2')).toBe(true);
  });
  it('ignores a dated revisit_by (no expiry filtering here)', () => {
    const ids = recordIds([
      doc('CVE-EXPIRED', [], { revisit_by: '2000-01-01' }),
    ]);
    expect(ids.has('CVE-EXPIRED')).toBe(true);
  });
  it('is total on malformed input (non-array, null docs, bad statements)', () => {
    expect(recordIds(undefined as unknown as unknown[]).size).toBe(0);
    expect(recordIds('x' as unknown as unknown[]).size).toBe(0);
    expect(recordIds([null, 42, { statements: 'nope' }]).size).toBe(0);
  });
});

describe('activeRecordIds', () => {
  const today = new Date('2026-07-22T12:00:00.000Z');
  function doc(name: string, revisit_by?: string): unknown {
    return {
      statements: [{ vulnerability: { name }, status: 'affected' }],
      ...(revisit_by === undefined ? {} : { revisit_by }),
    };
  }

  it('includes ids from records with no revisit_by', () => {
    const ids = activeRecordIds([doc('CVE-LIVE')], today);
    expect(ids.has('CVE-LIVE')).toBe(true);
  });
  it('includes ids from records whose dated revisit_by is in the future', () => {
    const ids = activeRecordIds([doc('CVE-FUTURE', '2026-10-01')], today);
    expect(ids.has('CVE-FUTURE')).toBe(true);
  });
  it('includes ids from event-token records (never expire)', () => {
    const ids = activeRecordIds(
      [doc('CVE-EVENT', 'wait-for-image-rebuild')],
      today,
    );
    expect(ids.has('CVE-EVENT')).toBe(true);
  });
  it('EXCLUDES ids from records whose dated revisit_by is overdue', () => {
    const ids = activeRecordIds([doc('CVE-STALE', '2026-01-01')], today);
    expect(ids.has('CVE-STALE')).toBe(false);
    expect(ids.size).toBe(0);
  });
  it('drops only the overdue doc, keeping live docs in the same set', () => {
    const ids = activeRecordIds(
      [doc('CVE-STALE', '2026-01-01'), doc('CVE-LIVE')],
      today,
    );
    expect(ids.has('CVE-STALE')).toBe(false);
    expect(ids.has('CVE-LIVE')).toBe(true);
    expect(ids.size).toBe(1);
  });
  it('is total on malformed input', () => {
    expect(activeRecordIds(undefined as unknown as unknown[], today).size).toBe(
      0,
    );
    expect(activeRecordIds([null, 42], today).size).toBe(0);
  });
});
