import {
  ghsaCveMap,
  ghsaToCve,
  advisoryRuleId,
  severityScore,
  toSarif,
} from '../../.github/scripts/npm-audit-to-sarif';

// Unit tests for .github/scripts/npm-audit-to-sarif.ts (issue #295): convert
// `npm audit --json` into a SARIF 2.1.0 document so npm audit becomes a
// first-class scanner — its findings reach the GitHub Security tab AND the Code
// Scanning Alerts API, which is what the VEX report (#189) reconciles against.
// This makes npm audit stop being the one vuln scanner that uploads no SARIF.
//
// THE CRUX — ruleId carries the CVE when resolvable. npm audit keys advisories
// by package and carries only a GHSA (in via[].url), no CVE. But the downstream
// consumers key on CVE: `vex-to-sarif-suppressions.ts` does extractCve(ruleId)
// to dismiss covered alerts, and `vex-report.ts` reconciles by CVE. So the
// converter takes the `.vex/` ledger too and, when a record aliases the GHSA to
// a CVE, emits a ruleId `CVE-…-<pkg>` (mirroring grype's `CVE-…-python` shape)
// so the finding reconciles as Accepted/Tracked. When no record resolves it, the
// bare GHSA is the ruleId (still a valid, if unreconciled, alert).
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124) +
// Stryker (#122) + fuzz-regression totality.

function auditDoc(vulns: Record<string, unknown>): unknown {
  return { auditReportVersion: 2, vulnerabilities: vulns };
}
function advisory(
  severity: string,
  url: string,
  title = 'some advisory',
): unknown {
  return { severity, via: [{ source: 1, name: 'x', title, url }] };
}
// A `.vex/` doc aliasing a GHSA to a CVE (the ledger the converter consults).
const vexDoc = (cve: string, ghsa: string) => ({
  statements: [
    { vulnerability: { name: cve, aliases: [ghsa] }, status: 'affected' },
  ],
});

describe('ghsaCveMap', () => {
  it('maps each GHSA alias to the statement’s CVE', () => {
    const m = ghsaCveMap([vexDoc('CVE-2026-13149', 'GHSA-3jxr-9vmj-r5cp')]);
    expect(m.get('GHSA-3JXR-9VMJ-R5CP')).toBe('CVE-2026-13149');
  });
  it('skips a statement whose ids carry no CVE', () => {
    const m = ghsaCveMap([
      {
        statements: [
          { vulnerability: { name: 'GHSA-only-xxxx-yyyy', aliases: [] } },
        ],
      },
    ]);
    expect(m.size).toBe(0);
  });
  it('is total: null docs / non-record docs / bad statements contribute nothing', () => {
    expect(ghsaCveMap([null, 42, 'x']).size).toBe(0);
    expect(ghsaCveMap([{ statements: 'nope' }]).size).toBe(0);
    expect(ghsaCveMap(undefined as unknown as unknown[]).size).toBe(0);
  });
});

describe('ghsaCveMap boundary', () => {
  it('does NOT map a non-GHSA sibling id even when a CVE is present', () => {
    // statement carries a CVE + a bogus non-GHSA alias — the non-GHSA must not
    // be added to the map (proves the GHSA_RE.test guard is load-bearing).
    const m = ghsaCveMap([
      {
        statements: [
          { vulnerability: { name: 'CVE-2026-1', aliases: ['NOT-A-GHSA'] } },
        ],
      },
    ]);
    expect(m.has('NOT-A-GHSA')).toBe(false);
    expect(m.size).toBe(0);
  });
  it('classifies a CVE by its normalized CVE- prefix', () => {
    const m = ghsaCveMap([vexDoc('CVE-2026-13149', 'GHSA-3jxr-9vmj-r5cp')]);
    expect(m.get('GHSA-3JXR-9VMJ-R5CP')).toBe('CVE-2026-13149');
  });
});

describe('ghsaToCve', () => {
  const map = new Map([['GHSA-3JXR-9VMJ-R5CP', 'CVE-2026-13149']]);
  it('resolves a known GHSA to its CVE (case-insensitive)', () => {
    expect(ghsaToCve('GHSA-3jxr-9vmj-r5cp', map)).toBe('CVE-2026-13149');
  });
  it('returns null for an unknown GHSA', () => {
    expect(ghsaToCve('GHSA-zzzz-zzzz-zzzz', map)).toBeNull();
  });
  it('returns null for a non-GHSA string even if that raw string is a map key', () => {
    // A non-GHSA string can never be looked up (ghsaIn returns null first) —
    // proves the `ghsa === null` early-return is load-bearing, not the map miss.
    const trickMap = new Map([['NOT-A-GHSA', 'CVE-2026-1']]);
    expect(ghsaToCve('NOT-A-GHSA', trickMap)).toBeNull();
  });
  it('returns null for a non-string', () => {
    expect(ghsaToCve(null, map)).toBeNull();
    expect(ghsaToCve(42, map)).toBeNull();
  });
});

describe('advisoryRuleId', () => {
  const map = new Map([['GHSA-3JXR-9VMJ-R5CP', 'CVE-2026-13149']]);
  it('emits CVE-<pkg> when the GHSA resolves to a ledger CVE', () => {
    expect(
      advisoryRuleId(
        'brace-expansion',
        advisory('high', 'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp'),
        map,
      ),
    ).toBe('CVE-2026-13149-brace-expansion');
  });
  it('falls back to the bare GHSA when no record resolves it', () => {
    expect(
      advisoryRuleId(
        'tar',
        advisory('high', 'https://github.com/advisories/GHSA-zzzz-zzzz-zzzz'),
        map,
      ),
    ).toBe('GHSA-ZZZZ-ZZZZ-ZZZZ');
  });
  it('uses the package name alone when the advisory carries no GHSA', () => {
    expect(
      advisoryRuleId('mystery', advisory('high', 'https://example.com/x'), map),
    ).toBe('mystery');
  });
  it('skips string/non-record via entries when collecting GHSAs', () => {
    // `via` mixing a package-ref string, a non-record, and one advisory object.
    const adv = {
      severity: 'high',
      via: [
        'brace-expansion',
        7,
        { url: 'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp' },
      ],
    };
    expect(advisoryRuleId('brace-expansion', adv, map)).toBe(
      'CVE-2026-13149-brace-expansion',
    );
  });
  it('skips a via entry whose url is not a string (falls back to pkg)', () => {
    // exercises ghsaIn's non-string guard (via.url = number/array/absent).
    const adv = { severity: 'high', via: [{ url: 42 }, { source: 1 }] };
    expect(advisoryRuleId('pkg', adv, map)).toBe('pkg');
  });
  it('does NOT extract a GHSA from a non-string url that String()-coerces to one', () => {
    // A single-element array whose String() form is a GHSA — proves ghsaIn's
    // `typeof !== 'string'` guard is load-bearing: without it, RegExp.exec would
    // coerce the array to its GHSA-looking string and falsely match.
    const adv = {
      severity: 'high',
      via: [{ url: ['GHSA-aaaa-bbbb-cccc'] }],
    };
    expect(advisoryRuleId('pkg', adv, map)).toBe('pkg');
  });
});

describe('severityScore', () => {
  it('maps npm severities to GitHub security-severity bands', () => {
    expect(severityScore('critical')).toBe('9.8');
    expect(severityScore('high')).toBe('8.1');
    expect(severityScore('moderate')).toBe('5.5');
    expect(severityScore('low')).toBe('2.0');
  });
  it('is UNKNOWN-safe: an unrecognized/absent severity → 0.0', () => {
    expect(severityScore('info')).toBe('0.0');
    expect(severityScore(undefined)).toBe('0.0');
    expect(severityScore(42)).toBe('0.0');
  });
});

describe('severity level mapping (via toSarif)', () => {
  const vd = [vexDoc('CVE-2026-13149', 'GHSA-3jxr-9vmj-r5cp')];
  const at = (severity: string) =>
    toSarif(auditDoc({ p: advisory(severity, 'https://example.com/x') }), vd)
      .runs[0].results[0].level;
  it('maps each npm severity to its SARIF level', () => {
    expect(at('critical')).toBe('error');
    expect(at('high')).toBe('error');
    expect(at('moderate')).toBe('warning');
    expect(at('low')).toBe('warning'); // distinct from moderate — kills the `low` entry mutant
    expect(at('info')).toBe('note');
  });
});

describe('toSarif', () => {
  const vexDocs = [vexDoc('CVE-2026-13149', 'GHSA-3jxr-9vmj-r5cp')];

  it('emits one result per advisory with the CVE-carrying ruleId', () => {
    const doc = auditDoc({
      'brace-expansion': advisory(
        'high',
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
        'brace-expansion DoS',
      ),
    });
    const sarif = toSarif(doc, vexDocs);
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('npm-audit');
    expect(sarif.runs[0].results).toHaveLength(1);
    const r = sarif.runs[0].results[0];
    expect(r.ruleId).toBe('CVE-2026-13149-brace-expansion');
    expect(r.level).toBe('error'); // high maps to error (serious)
    expect(r.properties['security-severity']).toBe('8.1');
    // EXACT message (kills the ghsaText / severity / pkg string mutants).
    expect(r.message.text).toBe(
      'npm audit: high severity advisory in brace-expansion (GHSA-3JXR-9VMJ-R5CP)',
    );
    expect(r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'package-lock.json',
    );
    // The document is a well-formed, uploadable SARIF 2.1.0 (exact $schema).
    expect(sarif.$schema).toBe(
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    );
    expect(sarif.runs[0].tool.driver.rules).toEqual([]);
  });
  it('omits the GHSA suffix from the message when there is no GHSA', () => {
    // kills the `ghsaText = ''` empty-string mutant AND the length>0 boundary.
    const doc = auditDoc({ mystery: advisory('low', 'https://example.com/x') });
    expect(toSarif(doc, vexDocs).runs[0].results[0].message.text).toBe(
      'npm audit: low severity advisory in mystery',
    );
  });
  it('joins multiple GHSAs with ", " in the message (kills the separator mutant)', () => {
    const doc = auditDoc({
      p: {
        severity: 'high',
        via: [
          { url: 'https://github.com/advisories/GHSA-aaaa-aaaa-aaaa' },
          { url: 'https://github.com/advisories/GHSA-bbbb-bbbb-bbbb' },
        ],
      },
    });
    expect(toSarif(doc, vexDocs).runs[0].results[0].message.text).toBe(
      'npm audit: high severity advisory in p (GHSA-AAAA-AAAA-AAAA, GHSA-BBBB-BBBB-BBBB)',
    );
  });
  it('level is error for a critical advisory', () => {
    const doc = auditDoc({
      tar: advisory(
        'critical',
        'https://github.com/advisories/GHSA-w8wr-v893-vjvp',
      ),
    });
    expect(toSarif(doc, vexDocs).runs[0].results[0].level).toBe('error');
  });
  it('level is warning for a moderate advisory', () => {
    const doc = auditDoc({
      pkg: advisory(
        'moderate',
        'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      ),
    });
    expect(toSarif(doc, vexDocs).runs[0].results[0].level).toBe('warning');
  });
  it('level is note for an unrecognized severity', () => {
    const doc = auditDoc({
      pkg: advisory(
        'info',
        'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      ),
    });
    expect(toSarif(doc, vexDocs).runs[0].results[0].level).toBe('note');
  });
  it('handles an advisory that is not a record (severity undefined → note)', () => {
    const sarif = toSarif(auditDoc({ weird: 42 }), vexDocs);
    expect(sarif.runs[0].results[0].level).toBe('note');
    expect(sarif.runs[0].results[0].ruleId).toBe('weird');
  });
  it('emits a valid empty-results SARIF for a clean audit', () => {
    const sarif = toSarif(auditDoc({}), vexDocs);
    expect(sarif.runs[0].results).toEqual([]);
    expect(sarif.version).toBe('2.1.0');
  });
  it('is total: malformed audit JSON yields a valid empty-results SARIF', () => {
    for (const bad of [undefined, null, 'x', 42, { vulnerabilities: 7 }]) {
      const sarif = toSarif(bad, vexDocs);
      expect(sarif.runs[0].results).toEqual([]);
      expect(sarif.version).toBe('2.1.0');
    }
  });
  it('tolerates missing vex docs (bare-GHSA ruleIds, still valid SARIF)', () => {
    const doc = auditDoc({
      'brace-expansion': advisory(
        'high',
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
      ),
    });
    const sarif = toSarif(doc, undefined as unknown as unknown[]);
    expect(sarif.runs[0].results[0].ruleId).toBe('GHSA-3JXR-9VMJ-R5CP');
  });
});
