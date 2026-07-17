import {
  vexAcceptedIds,
  matchVulnIds,
  hasSeverity,
  uncoveredVulns,
  normId,
  asArray,
  asRecord,
} from '../../.github/scripts/grype-fs-gate';

// Unit tests for .github/scripts/grype-fs-gate.ts (issue #284): derive the Grype
// FILESYSTEM scan's gate from its JSON, VEX-aware for BOTH statuses. Imported
// IN-PROCESS so it flows through the 100% coverage gate (#124) + Stryker
// mutation (#122) + the fuzz-regression tier's totality guarantee.
//
// GOVERNANCE-RELEVANT: this decides whether the required Grype FS check reds.
// The crux is that grype keeps `affected` VEX records in `matches[]` (only
// `not_affected`/`fixed` move to `ignoredMatches[]`), so the JSON gate must
// EXCLUDE the `.vex/`-accepted id set — an `affected` record is an explicit,
// reviewed acceptance just as a `not_affected` one is (#188 status-honesty).
// GHSA↔CVE aliasing is the make-or-break detail: grype may report the GHSA as
// the primary `vulnerability.id` with the CVE in `relatedVulnerabilities` (or
// vice versa), while the `.vex/` records name the CVE and alias the GHSA — the
// gate must map either direction onto the accepted set.
//
// The gate floor is grype's STRICTEST rung (#284, "drop it the most strict"):
// EVERY severity counts, so `hasSeverity` (not a High/Critical membership test)
// is the operative predicate — proven necessary because grype's
// `severity-cutoff`/`--fail-on` only sets the exit code, never filtering the
// JSON `matches[]`.

// -- small total coercions (mirroring gate-findings.test.ts / sarif-cve-ids) --
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
    expect(normId('cve-2026-52869')).toBe('CVE-2026-52869');
    expect(normId('  GHSA-jpw9-pfvf-9f58  ')).toBe('GHSA-JPW9-PFVF-9F58');
  });
  it('returns null for non-strings and empty/whitespace', () => {
    expect(normId(null)).toBeNull();
    expect(normId(123)).toBeNull();
    expect(normId('')).toBeNull();
    expect(normId('   ')).toBeNull();
    expect(normId(['CVE-2026-52869'])).toBeNull();
  });
});

describe('vexAcceptedIds', () => {
  // A minimal OpenVEX doc: one statement, one vulnerability (name + aliases).
  function vexDoc(
    name: string,
    aliases: string[],
    status = 'affected',
  ): unknown {
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [
        {
          vulnerability: { name, aliases },
          products: [{ '@id': 'pkg:pypi/mcp@1.23.3' }],
          status,
        },
      ],
    };
  }

  it('collects the name AND aliases of every statement, upper-cased', () => {
    const ids = vexAcceptedIds([
      vexDoc('CVE-2026-52869', ['GHSA-jpw9-pfvf-9f58']),
    ]);
    expect(ids.has('CVE-2026-52869')).toBe(true);
    expect(ids.has('GHSA-JPW9-PFVF-9F58')).toBe(true);
  });

  it('accepts BOTH affected and not_affected records (both are reviewed acceptances)', () => {
    const affected = vexAcceptedIds([
      vexDoc('CVE-2026-52869', ['GHSA-jpw9-pfvf-9f58'], 'affected'),
    ]);
    const notAffected = vexAcceptedIds([
      vexDoc('CVE-2024-23342', ['GHSA-wj6h-64fc-37mp'], 'not_affected'),
    ]);
    expect(affected.has('CVE-2026-52869')).toBe(true);
    expect(notAffected.has('CVE-2024-23342')).toBe(true);
  });

  it('unions ids across multiple docs', () => {
    const ids = vexAcceptedIds([
      vexDoc('CVE-2026-52869', ['GHSA-jpw9-pfvf-9f58']),
      vexDoc('CVE-2026-52870', ['GHSA-hvrp-rf83-w775']),
    ]);
    expect([...ids].sort()).toEqual([
      'CVE-2026-52869',
      'CVE-2026-52870',
      'GHSA-HVRP-RF83-W775',
      'GHSA-JPW9-PFVF-9F58',
    ]);
  });

  it('tolerates missing/garbage aliases and a missing name', () => {
    const ids = vexAcceptedIds([
      { statements: [{ vulnerability: { name: 'CVE-2026-1' } }] }, // no aliases
      // aliases array with a null + non-string element (both skipped) alongside
      // a real one — exercises the alias-null branch of the loop.
      {
        statements: [{ vulnerability: { aliases: [null, 42, 'GHSA-aaaa'] } }],
      }, // no name
      { statements: [{ vulnerability: { name: 42, aliases: 'nope' } }] }, // junk
    ]);
    expect(ids.has('CVE-2026-1')).toBe(true);
    expect(ids.has('GHSA-AAAA')).toBe(true);
    expect(ids.size).toBe(2);
  });

  it('is total on malformed input (no docs, non-object doc/statement/vuln)', () => {
    expect(vexAcceptedIds([]).size).toBe(0);
    expect(vexAcceptedIds([null, 3, 'x']).size).toBe(0);
    expect(vexAcceptedIds([{ statements: 'nope' }]).size).toBe(0);
    expect(vexAcceptedIds([{ statements: [null, 5] }]).size).toBe(0);
    expect(
      vexAcceptedIds([{ statements: [{ vulnerability: null }] }]).size,
    ).toBe(0);
    expect(vexAcceptedIds('not-an-array' as unknown as unknown[]).size).toBe(0);
  });
});

describe('matchVulnIds', () => {
  it('collects the primary id AND every relatedVulnerabilities id, upper-cased', () => {
    const ids = matchVulnIds({
      vulnerability: { id: 'GHSA-jpw9-pfvf-9f58', severity: 'High' },
      relatedVulnerabilities: [{ id: 'CVE-2026-52869' }],
    });
    expect(ids.has('GHSA-JPW9-PFVF-9F58')).toBe(true);
    expect(ids.has('CVE-2026-52869')).toBe(true);
  });

  it('tolerates a non-record match (null/primitive/array) — early return', () => {
    expect(matchVulnIds(null).size).toBe(0);
    expect(matchVulnIds('nope').size).toBe(0);
    expect(matchVulnIds([]).size).toBe(0);
  });

  it('tolerates a missing/garbage vulnerability and relatedVulnerabilities', () => {
    expect(matchVulnIds({}).size).toBe(0);
    expect(matchVulnIds({ vulnerability: null }).size).toBe(0);
    expect(matchVulnIds({ vulnerability: { id: 42 } }).size).toBe(0);
    expect(
      matchVulnIds({
        vulnerability: { id: 'CVE-2026-1' },
        relatedVulnerabilities: [null, 5, { id: 42 }],
      }),
    ).toEqual(new Set(['CVE-2026-1']));
  });
});

describe('hasSeverity (strictest floor — every severity counts)', () => {
  it('is true for ANY string severity, including the lowest rungs', () => {
    expect(hasSeverity({ vulnerability: { severity: 'Critical' } })).toBe(true);
    expect(hasSeverity({ vulnerability: { severity: 'High' } })).toBe(true);
    expect(hasSeverity({ vulnerability: { severity: 'Medium' } })).toBe(true);
    expect(hasSeverity({ vulnerability: { severity: 'Low' } })).toBe(true);
    expect(hasSeverity({ vulnerability: { severity: 'Negligible' } })).toBe(
      true,
    );
    // Even an unrecognized string severity is a real finding at the strictest
    // floor — the gate errs toward surfacing, not silently dropping.
    expect(hasSeverity({ vulnerability: { severity: 'Unknown' } })).toBe(true);
  });
  it('is false for a missing/garbage vulnerability or a non-string severity', () => {
    expect(hasSeverity({})).toBe(false);
    expect(hasSeverity({ vulnerability: null })).toBe(false);
    expect(hasSeverity({ vulnerability: { severity: 42 } })).toBe(false);
    expect(hasSeverity({ vulnerability: {} })).toBe(false);
  });
});

describe('uncoveredVulns (the gate decision — strictest floor)', () => {
  // Grype JSON shape: matches[] with vulnerability.{id,severity} + related[].
  function grypeJson(...matches: unknown[]): unknown {
    return { matches };
  }
  // The 3 mcp records' accepted id set (both the CVE names and GHSA aliases).
  const mcpAccepted = vexAcceptedIds([
    {
      statements: [
        {
          vulnerability: {
            name: 'CVE-2026-52869',
            aliases: ['GHSA-jpw9-pfvf-9f58'],
          },
          status: 'affected',
        },
      ],
    },
    {
      statements: [
        {
          vulnerability: {
            name: 'CVE-2026-52870',
            aliases: ['GHSA-hvrp-rf83-w775'],
          },
          status: 'affected',
        },
      ],
    },
    {
      statements: [
        {
          vulnerability: {
            name: 'CVE-2026-59950',
            aliases: ['GHSA-vj7q-gjh5-988w'],
          },
          status: 'affected',
        },
      ],
    },
  ]);

  it('PASSES with the 3 mcp GHSAs present (reported by GHSA id, CVE in related) — VEX-accepted', () => {
    // Exactly the #284 scenario: grype rates the GHSA high, carries the CVE as
    // a related vulnerability, and the .vex/ records are `affected`.
    const doc = grypeJson(
      {
        vulnerability: { id: 'GHSA-jpw9-pfvf-9f58', severity: 'High' },
        relatedVulnerabilities: [{ id: 'CVE-2026-52869' }],
      },
      {
        vulnerability: { id: 'GHSA-hvrp-rf83-w775', severity: 'High' },
        relatedVulnerabilities: [{ id: 'CVE-2026-52870' }],
      },
      {
        vulnerability: { id: 'GHSA-vj7q-gjh5-988w', severity: 'High' },
        relatedVulnerabilities: [{ id: 'CVE-2026-59950' }],
      },
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([]);
  });

  it('accepts a match whether grype reports the CVE OR the GHSA as primary (aliasing both ways)', () => {
    // CVE primary, no related (grype names the CVE).
    const cvePrimary = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
    });
    // GHSA primary, no related (grype names only the GHSA).
    const ghsaPrimary = grypeJson({
      vulnerability: { id: 'GHSA-hvrp-rf83-w775', severity: 'Critical' },
    });
    expect(uncoveredVulns(cvePrimary, mcpAccepted)).toEqual([]);
    expect(uncoveredVulns(ghsaPrimary, mcpAccepted)).toEqual([]);
  });

  it('FAILS on a genuinely NEW uncovered CVE (no .vex/ record)', () => {
    const doc = grypeJson({
      vulnerability: { id: 'CVE-2099-99999', severity: 'High' },
    });
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual(['CVE-2099-99999']);
  });

  it('reports ONLY the uncovered ids when accepted and uncovered are mixed', () => {
    const doc = grypeJson(
      // accepted (affected mcp)
      {
        vulnerability: { id: 'GHSA-jpw9-pfvf-9f58', severity: 'High' },
        relatedVulnerabilities: [{ id: 'CVE-2026-52869' }],
      },
      // uncovered new critical
      { vulnerability: { id: 'CVE-2099-11111', severity: 'Critical' } },
      // uncovered new high
      { vulnerability: { id: 'CVE-2099-22222', severity: 'High' } },
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([
      'CVE-2099-11111',
      'CVE-2099-22222',
    ]);
  });

  it('FAILS on uncovered Medium/Low/Negligible findings too (strictest floor, #284)', () => {
    // The #284 pytest case in miniature: a Medium finding with no .vex/ record
    // must fail once the floor is dropped to the strictest rung. Low/Negligible
    // likewise — nothing is below the floor anymore.
    const doc = grypeJson(
      { vulnerability: { id: 'CVE-2099-33333', severity: 'Medium' } },
      { vulnerability: { id: 'CVE-2099-44444', severity: 'Low' } },
      { vulnerability: { id: 'CVE-2099-55555', severity: 'Negligible' } },
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([
      'CVE-2099-33333',
      'CVE-2099-44444',
      'CVE-2099-55555',
    ]);
  });

  it('a VEX-covered low-severity finding still PASSES (coverage, not severity, decides)', () => {
    const accepted = new Set(['CVE-2099-66666']);
    const doc = grypeJson({
      vulnerability: { id: 'CVE-2099-66666', severity: 'Negligible' },
    });
    expect(uncoveredVulns(doc, accepted)).toEqual([]);
  });

  it('de-duplicates and sorts the uncovered id list deterministically', () => {
    const doc = grypeJson(
      { vulnerability: { id: 'CVE-2099-22222', severity: 'High' } },
      { vulnerability: { id: 'CVE-2099-11111', severity: 'High' } },
      { vulnerability: { id: 'CVE-2099-22222', severity: 'Critical' } }, // dup id
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([
      'CVE-2099-11111',
      'CVE-2099-22222',
    ]);
  });

  it('labels an uncovered match with no readable primary id as (unknown)', () => {
    const doc = grypeJson({ vulnerability: { severity: 'High' } });
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual(['(unknown)']);
  });

  it('is total on malformed grype JSON (non-object doc, bad matches, junk match)', () => {
    expect(uncoveredVulns(null, mcpAccepted)).toEqual([]);
    expect(uncoveredVulns('nope', mcpAccepted)).toEqual([]);
    expect(uncoveredVulns({ matches: 'nope' }, mcpAccepted)).toEqual([]);
    expect(uncoveredVulns({ matches: [null, 5] }, mcpAccepted)).toEqual([]);
    expect(uncoveredVulns({}, mcpAccepted)).toEqual([]);
  });

  it('with an EMPTY accepted set, every match is uncovered (fail-closed)', () => {
    const doc = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
    });
    expect(uncoveredVulns(doc, new Set())).toEqual(['CVE-2026-52869']);
  });
});
