import {
  matchVulnIds,
  matchPurl,
  hasSeverity,
  uncoveredVulns,
  normId,
  asArray,
  asRecord,
} from '../../.github/scripts/grype-fs-gate';
import { recordAcceptances } from '../../.github/scripts/vex-ledger';

// Unit tests for .github/scripts/grype-fs-gate.ts (issue #284): derive the Grype
// FILESYSTEM scan's gate from its JSON, VEX-aware for BOTH statuses. Imported
// IN-PROCESS so it flows through the 100% coverage gate (#124) + Stryker
// mutation (#122) + the fuzz-regression tier's totality guarantee.
//
// GOVERNANCE-RELEVANT: this decides whether the required Grype FS check reds.
// The crux is that grype keeps `affected` VEX records in `matches[]` (only
// `not_affected`/`fixed` move to `ignoredMatches[]`), so the JSON gate must
// EXCLUDE the `.vex/`-accepted findings — an `affected` record is an explicit,
// reviewed acceptance just as a `not_affected` one is (#188 status-honesty).
// GHSA↔CVE aliasing is the make-or-break detail: grype may report the GHSA as
// the primary `vulnerability.id` with the CVE in `relatedVulnerabilities` (or
// vice versa), while the `.vex/` records name the CVE and alias the GHSA — the
// gate must map either direction onto the accepted set.
//
// AND coverage is SURFACE-SCOPED (#337): an id match alone is not coverage. Each
// acceptance also names the product purl it argues about, and the gate compares
// it against the match's `artifact.purl`, so an image-scoped `pkg:deb/...` record
// can no longer suppress a same-CVE finding on the repo tree's `pkg:npm/...`
// copy. That was over-suppression — the one direction this repo's posture forbids
// (#335 C2). The purl parser/matcher itself is tested in vex-ledger.test.ts (its
// home); the cases here are the GATE's half of the contract.
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

// NB the acceptance BUILDER (`recordAcceptances`) and the purl parser/matcher it
// relies on live in `vex-ledger.ts` and are tested there — one home for the "what
// does a `.vex/` record cover" question, shared by this gate and the npm-audit
// gate (#295/#337). What belongs here is the GATE's half: reading the finding's
// own surface out of grype's JSON, and the coverage decision that combines them.

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
  // Grype JSON shape: matches[] with vulnerability.{id,severity}, related[], and
  // the `artifact` the finding was reported ON — whose purl is the SURFACE a
  // `.vex/` record has to argue about to cover it (#337).
  function grypeJson(...matches: unknown[]): unknown {
    return { matches };
  }
  // The pypi package the 3 real `.vex/mcp-CVE-*.openvex.json` records argue
  // about. Every mcp fixture below is a finding on THAT surface, so the coverage
  // assertions exercise the identifier and the purl halves together.
  const MCP_PURL = 'pkg:pypi/mcp@1.23.3';
  function onMcp(
    vulnerability: unknown,
    relatedVulnerabilities?: unknown[],
  ): unknown {
    return {
      vulnerability,
      ...(relatedVulnerabilities === undefined
        ? {}
        : { relatedVulnerabilities }),
      artifact: { name: 'mcp', version: '1.23.3', purl: MCP_PURL },
    };
  }
  // A single-statement OpenVEX doc naming one CVE + its GHSA alias, scoped to the
  // mcp pypi product (the real records carry exactly this shape).
  function mcpDoc(name: string, alias: string, status = 'affected'): unknown {
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [
        {
          vulnerability: { name, aliases: [alias] },
          products: [{ '@id': MCP_PURL, identifiers: { purl: MCP_PURL } }],
          status,
        },
      ],
    };
  }
  // The 3 mcp records as the gate sees them: for each, the accepted id set (CVE
  // name + GHSA alias) AND the product purl it argues about.
  const mcpAccepted = recordAcceptances([
    mcpDoc('CVE-2026-52869', 'GHSA-jpw9-pfvf-9f58'),
    mcpDoc('CVE-2026-52870', 'GHSA-hvrp-rf83-w775'),
    mcpDoc('CVE-2026-59950', 'GHSA-vj7q-gjh5-988w'),
  ]);

  it('PASSES with the 3 mcp GHSAs present (reported by GHSA id, CVE in related) — VEX-accepted', () => {
    // Exactly the #284 scenario: grype rates the GHSA high, carries the CVE as
    // a related vulnerability, and the .vex/ records are `affected`.
    const doc = grypeJson(
      onMcp({ id: 'GHSA-jpw9-pfvf-9f58', severity: 'High' }, [
        { id: 'CVE-2026-52869' },
      ]),
      onMcp({ id: 'GHSA-hvrp-rf83-w775', severity: 'High' }, [
        { id: 'CVE-2026-52870' },
      ]),
      onMcp({ id: 'GHSA-vj7q-gjh5-988w', severity: 'High' }, [
        { id: 'CVE-2026-59950' },
      ]),
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([]);
  });

  it('accepts a match whether grype reports the CVE OR the GHSA as primary (aliasing both ways)', () => {
    // CVE primary, no related (grype names the CVE).
    const cvePrimary = grypeJson(
      onMcp({ id: 'CVE-2026-52869', severity: 'High' }),
    );
    // GHSA primary, no related (grype names only the GHSA).
    const ghsaPrimary = grypeJson(
      onMcp({ id: 'GHSA-hvrp-rf83-w775', severity: 'Critical' }),
    );
    expect(uncoveredVulns(cvePrimary, mcpAccepted)).toEqual([]);
    expect(uncoveredVulns(ghsaPrimary, mcpAccepted)).toEqual([]);
  });

  it('FAILS on a genuinely NEW uncovered CVE (no .vex/ record)', () => {
    const doc = grypeJson(onMcp({ id: 'CVE-2099-99999', severity: 'High' }));
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual(['CVE-2099-99999']);
  });

  it('reports ONLY the uncovered ids when accepted and uncovered are mixed', () => {
    const doc = grypeJson(
      // accepted (affected mcp)
      onMcp({ id: 'GHSA-jpw9-pfvf-9f58', severity: 'High' }, [
        { id: 'CVE-2026-52869' },
      ]),
      // uncovered new critical
      onMcp({ id: 'CVE-2099-11111', severity: 'Critical' }),
      // uncovered new high
      onMcp({ id: 'CVE-2099-22222', severity: 'High' }),
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
      onMcp({ id: 'CVE-2099-33333', severity: 'Medium' }),
      onMcp({ id: 'CVE-2099-44444', severity: 'Low' }),
      onMcp({ id: 'CVE-2099-55555', severity: 'Negligible' }),
    );
    expect(uncoveredVulns(doc, mcpAccepted)).toEqual([
      'CVE-2099-33333',
      'CVE-2099-44444',
      'CVE-2099-55555',
    ]);
  });

  it('a VEX-covered low-severity finding still PASSES (coverage, not severity, decides)', () => {
    const accepted = recordAcceptances([
      mcpDoc('CVE-2099-66666', 'GHSA-aaaa-bbbb-cccc', 'not_affected'),
    ]);
    const doc = grypeJson(
      onMcp({ id: 'CVE-2099-66666', severity: 'Negligible' }),
    );
    expect(uncoveredVulns(doc, accepted)).toEqual([]);
  });

  it('de-duplicates and sorts the uncovered id list deterministically', () => {
    const doc = grypeJson(
      onMcp({ id: 'CVE-2099-22222', severity: 'High' }),
      onMcp({ id: 'CVE-2099-11111', severity: 'High' }),
      onMcp({ id: 'CVE-2099-22222', severity: 'Critical' }), // dup id
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

  it('with NO acceptances, every match is uncovered (fail-closed)', () => {
    const doc = grypeJson(onMcp({ id: 'CVE-2026-52869', severity: 'High' }));
    expect(uncoveredVulns(doc, [])).toEqual(['CVE-2026-52869']);
  });

  it('a finding with NO parseable purl is never covered, even on a matching id (#337 fail-closed)', () => {
    // Without a purl the finding's surface is unprovable, so no record can be
    // shown to argue about it. The honest verdict is to SURFACE it: a record must
    // never cover a finding whose surface we cannot establish. (Grype always
    // emits a purl for a real package match, so this is the degenerate case.)
    const noArtifact = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
    });
    const noPurl = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
      artifact: { name: 'mcp', version: '1.23.3' },
    });
    const junkPurl = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
      artifact: { name: 'mcp', purl: 'mcp@1.23.3' }, // not a purl at all
    });
    expect(uncoveredVulns(noArtifact, mcpAccepted)).toEqual(['CVE-2026-52869']);
    expect(uncoveredVulns(noPurl, mcpAccepted)).toEqual(['CVE-2026-52869']);
    expect(uncoveredVulns(junkPurl, mcpAccepted)).toEqual(['CVE-2026-52869']);
  });

  it('a same-CVE finding on a DIFFERENT pypi package is not covered (name is compared, not just type)', () => {
    // The mcp records argue about `pkg:pypi/mcp`. A same-CVE finding on another
    // pypi distribution is a different surface and must stay visible.
    const other = grypeJson({
      vulnerability: { id: 'CVE-2026-52869', severity: 'High' },
      artifact: { name: 'ecdsa', purl: 'pkg:pypi/ecdsa@0.19.2' },
    });
    expect(uncoveredVulns(other, mcpAccepted)).toEqual(['CVE-2026-52869']);
  });

  it('an image-scoped pkg:deb record does NOT cover a pkg:npm finding on the same CVE (#337)', () => {
    // THE OVER-SUPPRESSION REGRESSION. `.vex/CVE-2026-13149.openvex.json` is an
    // image-scoped acceptance: its reachability argument is made ONLY for the
    // Debian `node-brace-expansion` package inside the pinned MiniStack image.
    // The repo TREE carries a separate, independently-installed
    // `pkg:npm/brace-expansion` copy whose reachability that record never
    // argues. Matching on the identifier alone let the image record silently
    // suppress the npm finding here — over-suppression, the one direction this
    // repo's posture forbids (#335 C2). The gate must compare the record's own
    // product purl against the finding's `artifact.purl`.
    const imageScoped = recordAcceptances([
      {
        statements: [
          {
            vulnerability: {
              name: 'CVE-2026-13149',
              aliases: ['GHSA-v6h2-p8h4-qcjw'],
            },
            products: [
              {
                '@id': 'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2',
                identifiers: {
                  purl: 'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2',
                },
              },
            ],
            status: 'not_affected',
          },
        ],
      },
    ]);
    const npmFinding = grypeJson({
      vulnerability: { id: 'CVE-2026-13149', severity: 'High' },
      artifact: {
        name: 'brace-expansion',
        purl: 'pkg:npm/brace-expansion@2.0.1',
      },
    });
    expect(uncoveredVulns(npmFinding, imageScoped)).toEqual(['CVE-2026-13149']);
    // …while the SAME record still covers the image finding it was written for
    // (the fix scopes coverage, it does not remove it — nothing gets louder that
    // was legitimately accepted, and nothing gets quieter, #335 C2).
    const debFinding = grypeJson({
      vulnerability: { id: 'CVE-2026-13149', severity: 'High' },
      artifact: {
        name: 'node-brace-expansion',
        // Grype emits distro/arch/epoch qualifiers the record does not carry —
        // the comparison is qualifier-INSENSITIVE (subset), per .vex/README.md.
        purl: 'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2?arch=all&distro=debian-13',
      },
    });
    expect(uncoveredVulns(debFinding, imageScoped)).toEqual([]);
  });
});

describe('matchPurl (the finding’s own surface)', () => {
  it('parses the artifact purl grype reports for a match', () => {
    expect(
      matchPurl({
        vulnerability: { id: 'CVE-2026-13149' },
        artifact: {
          name: 'brace-expansion',
          purl: 'pkg:npm/brace-expansion@2.0.1',
        },
      }),
    ).toEqual({
      type: 'npm',
      namespace: '',
      name: 'brace-expansion',
      version: '2.0.1',
      qualifiers: new Map(),
    });
  });

  it('returns null for a non-record match, a missing/garbage artifact, and an unparseable purl', () => {
    expect(matchPurl(null)).toBeNull();
    expect(matchPurl('nope')).toBeNull();
    expect(matchPurl({})).toBeNull();
    expect(matchPurl({ artifact: null })).toBeNull();
    expect(matchPurl({ artifact: 'nope' })).toBeNull();
    expect(matchPurl({ artifact: {} })).toBeNull();
    expect(matchPurl({ artifact: { purl: 42 } })).toBeNull();
    expect(
      matchPurl({ artifact: { purl: 'brace-expansion@2.0.1' } }),
    ).toBeNull();
  });
});
