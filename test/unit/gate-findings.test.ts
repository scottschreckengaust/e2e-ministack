import {
  parseGrypeGate,
  parseTrivyGate,
  mergeGateSeverities,
  normGateSeverity,
  extractCve,
  asArray,
  asRecord,
} from '../../.github/scripts/gate-findings';

// Unit tests for .github/scripts/gate-findings.ts (#208): extract each scanner's
// GATE (distro-adjusted) severity per CVE from its structured JSON. Imported
// IN-PROCESS so it flows through the 100% coverage gate (#124) + Stryker
// mutation (#122). Output feeds the report's gate-vs-badge divergence column,
// so correctness is governance-relevant: a wrong gate rating would misrepresent
// how a VEX-accepted CVE was assessed.

describe('normGateSeverity', () => {
  it('normalizes grype Title-case and trivy UPPER-case to the shared vocab', () => {
    expect(normGateSeverity('Negligible')).toBe('NEGLIGIBLE');
    expect(normGateSeverity('High')).toBe('HIGH');
    expect(normGateSeverity('CRITICAL')).toBe('CRITICAL');
    expect(normGateSeverity('low')).toBe('LOW');
    expect(normGateSeverity('Medium')).toBe('MEDIUM');
  });
  it('maps an unknown/empty/non-string severity to UNKNOWN', () => {
    expect(normGateSeverity('bogus')).toBe('UNKNOWN');
    expect(normGateSeverity('')).toBe('UNKNOWN');
    expect(normGateSeverity(undefined)).toBe('UNKNOWN');
    expect(normGateSeverity(null)).toBe('UNKNOWN');
    expect(normGateSeverity(42)).toBe('UNKNOWN');
    // A non-string that stringifies to a keyword must NOT match (typeof guard).
    expect(normGateSeverity(['HIGH'])).toBe('UNKNOWN');
  });
});

describe('extractCve', () => {
  it('pulls a CVE (any case) from grype/trivy ids', () => {
    expect(extractCve('CVE-2019-1010022')).toBe('CVE-2019-1010022');
    expect(extractCve('cve-2026-1')).toBe('CVE-2026-1');
  });
  it('returns null for a non-CVE id or non-string', () => {
    expect(extractCve('GHSA-xxxx-yyyy-zzzz')).toBeNull();
    expect(extractCve(undefined)).toBeNull();
    expect(extractCve(['CVE-2026-1'])).toBeNull(); // typeof guard
  });
});

describe('parseGrypeGate', () => {
  // A minimal real-shaped grype JSON (severity is Title-case).
  const grype = {
    matches: [
      {
        vulnerability: { id: 'CVE-2019-1010022', severity: 'Negligible' },
        artifact: { name: 'libc6' },
      },
      {
        vulnerability: { id: 'CVE-2026-11822-x', severity: 'High' },
        artifact: { name: 'libsqlite3-0' },
      },
    ],
  };

  it('maps CVE -> normalized gate severity from matches[].vulnerability', () => {
    const m = parseGrypeGate(grype);
    expect(m.get('CVE-2019-1010022')).toBe('NEGLIGIBLE');
    expect(m.get('CVE-2026-11822')).toBe('HIGH'); // package suffix stripped
    expect(m.size).toBe(2);
  });

  it('keeps the HIGHER rank when a CVE appears on multiple packages', () => {
    const m = parseGrypeGate({
      matches: [
        { vulnerability: { id: 'CVE-2026-1', severity: 'Low' } },
        { vulnerability: { id: 'CVE-2026-1', severity: 'High' } }, // outranks
        { vulnerability: { id: 'CVE-2026-1', severity: 'Medium' } }, // lower, ignored
      ],
    });
    expect(m.get('CVE-2026-1')).toBe('HIGH');
  });

  it('skips a non-CVE id, a match/vuln that is not a record, and non-object matches', () => {
    const m = parseGrypeGate({
      matches: [
        'x',
        7,
        null,
        { vulnerability: 42 },
        { vulnerability: { id: 'GHSA-a-b-c', severity: 'High' } }, // not a CVE
        { vulnerability: { id: 'CVE-2026-9', severity: 'Medium' } },
      ],
    });
    expect([...m]).toEqual([['CVE-2026-9', 'MEDIUM']]);
  });

  it('returns an empty map for a non-object / missing matches', () => {
    expect(parseGrypeGate(null).size).toBe(0);
    expect(parseGrypeGate('x').size).toBe(0);
    expect(parseGrypeGate([1, 2]).size).toBe(0);
    expect(parseGrypeGate({}).size).toBe(0);
    expect(parseGrypeGate({ matches: 'nope' }).size).toBe(0);
  });

  it('maps an unrecognized/absent severity to the literal UNKNOWN (kills the RANK_NAME[0] mutant)', () => {
    // A CVE whose gate severity the scanner leaves blank/bogus must round-trip
    // to the exact string 'UNKNOWN' (rank 0) — not '' — so the report renders a
    // real word. This exercises RANK_NAME[0], which no other case reaches.
    const m = parseGrypeGate({
      matches: [
        { vulnerability: { id: 'CVE-2026-7', severity: 'not-a-severity' } },
        { vulnerability: { id: 'CVE-2026-8' } }, // severity absent
      ],
    });
    expect(m.get('CVE-2026-7')).toBe('UNKNOWN');
    expect(m.get('CVE-2026-8')).toBe('UNKNOWN');
  });
});

describe('parseTrivyGate', () => {
  // A minimal real-shaped trivy JSON (Severity is UPPER-case; a Result may omit
  // Vulnerabilities entirely).
  const trivy = {
    SchemaVersion: 2,
    Results: [
      {
        Target: 'img',
        Vulnerabilities: [
          { VulnerabilityID: 'CVE-2019-1010022', Severity: 'LOW' },
          { VulnerabilityID: 'CVE-2026-11822', Severity: 'HIGH' },
        ],
      },
      { Target: 'no-vulns' }, // Vulnerabilities absent
    ],
  };

  it('maps CVE -> normalized gate severity from Results[].Vulnerabilities[]', () => {
    const m = parseTrivyGate(trivy);
    expect(m.get('CVE-2019-1010022')).toBe('LOW');
    expect(m.get('CVE-2026-11822')).toBe('HIGH');
    expect(m.size).toBe(2);
  });

  it('keeps the HIGHER rank across duplicate CVE entries', () => {
    const m = parseTrivyGate({
      Results: [
        {
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-2026-2', Severity: 'MEDIUM' },
          ],
        },
        {
          Vulnerabilities: [
            { VulnerabilityID: 'CVE-2026-2', Severity: 'CRITICAL' },
          ],
        },
      ],
    });
    expect(m.get('CVE-2026-2')).toBe('CRITICAL');
  });

  it('skips non-record results, non-array Vulnerabilities, non-record vulns, non-CVE ids', () => {
    const m = parseTrivyGate({
      Results: [
        'x',
        7,
        null,
        { Vulnerabilities: 'nope' },
        {
          Vulnerabilities: [
            'y',
            9,
            null,
            { VulnerabilityID: 'not-a-cve', Severity: 'HIGH' },
            { VulnerabilityID: 'CVE-2026-3', Severity: 'HIGH' },
          ],
        },
      ],
    });
    expect([...m]).toEqual([['CVE-2026-3', 'HIGH']]);
  });

  it('returns an empty map for a non-object / missing Results', () => {
    expect(parseTrivyGate(null).size).toBe(0);
    expect(parseTrivyGate('x').size).toBe(0);
    expect(parseTrivyGate({}).size).toBe(0);
    expect(parseTrivyGate({ Results: 'nope' }).size).toBe(0);
  });
});

describe('mergeGateSeverities', () => {
  it('unions grype + trivy maps, keeping the HIGHER rank per CVE', () => {
    const grype = new Map([
      ['CVE-2019-1010022', 'NEGLIGIBLE'],
      ['CVE-2026-11822', 'HIGH'],
    ]);
    const trivy = new Map([
      ['CVE-2019-1010022', 'LOW'], // outranks NEGLIGIBLE
      ['CVE-2026-99', 'CRITICAL'], // trivy-only
    ]);
    const m = mergeGateSeverities([grype, trivy]);
    expect(m.get('CVE-2019-1010022')).toBe('LOW'); // max(NEGLIGIBLE, LOW)
    expect(m.get('CVE-2026-11822')).toBe('HIGH');
    expect(m.get('CVE-2026-99')).toBe('CRITICAL');
    expect(m.size).toBe(3);
  });

  it('skips null/undefined/non-Map entries and a non-array argument', () => {
    const grype = new Map([['CVE-2026-1', 'HIGH']]);
    expect([
      ...mergeGateSeverities([grype, null, undefined, {} as never]),
    ]).toEqual([['CVE-2026-1', 'HIGH']]);
    expect(mergeGateSeverities('nope' as unknown as never[]).size).toBe(0);
  });

  it('does not lower an already-higher merged value from a later map', () => {
    const a = new Map([['CVE-2026-1', 'CRITICAL']]);
    const b = new Map([['CVE-2026-1', 'LOW']]);
    expect(mergeGateSeverities([a, b]).get('CVE-2026-1')).toBe('CRITICAL');
  });
});

// The coercion helpers are exported + tested directly (like alerts-findings.ts /
// sarif-cve-ids.ts) so every branch is observable — asserting the RETURNED value
// kills the `if (false)` / `["Stryker was here"]` mutants inline use would miss.
describe('coercion helpers (tested directly — every branch observable)', () => {
  it('asArray: array passes by reference; anything else => a fresh []', () => {
    const a = [1];
    expect(asArray(a)).toBe(a);
    expect(asArray('x')).toEqual([]);
    expect(asArray(null)).toEqual([]);
    expect(asArray(undefined)).toEqual([]);
    expect(asArray({})).toEqual([]);
    expect(asArray(42)).toEqual([]);
  });
  it('asRecord: plain object passes; array/null/primitive => null', () => {
    const o = { a: 1 };
    expect(asRecord(o)).toBe(o);
    expect(asRecord([1])).toBeNull();
    expect(asRecord(null)).toBeNull();
    expect(asRecord('x')).toBeNull();
    expect(asRecord(3)).toBeNull();
    expect(asRecord(undefined)).toBeNull();
  });
});
