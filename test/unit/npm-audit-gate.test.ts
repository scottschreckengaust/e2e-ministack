import {
  extractGhsa,
  advisoryGhsaIds,
  uncoveredAdvisories,
  coveredAdvisories,
  resolveNow,
  gateResult,
} from '../../.github/scripts/npm-audit-gate';
import { activeRecordIds } from '../../.github/scripts/vex-ledger';

// Unit tests for .github/scripts/npm-audit-gate.ts (issue #295): derive the
// `npm audit` gate from its JSON output, VEX-aware against the shared `.vex/`
// ledger (via vex-ledger.ts). This is the 5th scanner surface #251 omitted, and
// the FIRST that must match on the GHSA — `npm audit --json` keys advisories by
// vulnerable PACKAGE name and carries the id ONLY as a GitHub advisory URL in
// `via[].url` (no CVE). So a `.vex/` record must name/alias the GHSA; the shared
// matcher already unions name ∪ aliases, so a base-image record naming the CVE +
// aliasing the GHSA covers here too.
//
// TWO outputs, mirroring the two-tier visibility model (#188):
//   - uncoveredAdvisories → the FAIL signal (a live advisory with no record).
//   - coveredAdvisories   → the TRANSPARENCY signal: accepted-but-present, so
//     the shim can PRINT them (npm audit has no Security tab; the log is the
//     visibility view). An `affected` record passes the gate but stays printed.
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124) +
// Stryker (#122) + the fuzz-regression tier's totality guarantee.

// A minimal `npm audit --json` doc: `vulnerabilities` keyed by package name,
// each with a `via[]` whose object entries carry the advisory `url`.
function auditDoc(vulns: Record<string, { via?: unknown }>): unknown {
  return { auditReportVersion: 2, vulnerabilities: vulns };
}
function advisory(...urls: string[]): { via: unknown[] } {
  return {
    via: urls.map((url) => ({ source: 1, name: 'x', title: 't', url })),
  };
}

describe('extractGhsa', () => {
  it('extracts the canonical (upper-case) GHSA from an advisory URL', () => {
    expect(
      extractGhsa('https://github.com/advisories/GHSA-3jxr-9vmj-r5cp'),
    ).toBe('GHSA-3JXR-9VMJ-R5CP');
  });
  it('returns null when no GHSA token is present', () => {
    expect(extractGhsa('https://example.com/CVE-2026-13149')).toBeNull();
    expect(extractGhsa('')).toBeNull();
  });
  it('returns null for non-strings (totality)', () => {
    expect(extractGhsa(null)).toBeNull();
    expect(extractGhsa(42)).toBeNull();
    expect(extractGhsa(['GHSA-3jxr-9vmj-r5cp'])).toBeNull();
  });
});

describe('advisoryGhsaIds', () => {
  it('collects the GHSA from every object via[].url', () => {
    const ids = advisoryGhsaIds(
      advisory(
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
        'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      ),
    );
    expect([...ids].sort()).toEqual([
      'GHSA-3JXR-9VMJ-R5CP',
      'GHSA-AAAA-BBBB-CCCC',
    ]);
  });
  it('ignores string via[] entries (package refs, not advisories)', () => {
    const ids = advisoryGhsaIds({
      via: [
        'brace-expansion',
        { url: 'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp' },
      ],
    });
    expect([...ids]).toEqual(['GHSA-3JXR-9VMJ-R5CP']);
  });
  it('is empty for an advisory whose via carries no GHSA url', () => {
    expect(advisoryGhsaIds(advisory('https://example.com/x')).size).toBe(0);
  });
  it('is total on malformed input', () => {
    expect(advisoryGhsaIds(null).size).toBe(0);
    expect(advisoryGhsaIds('x').size).toBe(0);
    expect(advisoryGhsaIds({ via: 42 }).size).toBe(0);
    expect(advisoryGhsaIds({ via: [null, 7, 'x'] }).size).toBe(0);
  });
});

describe('uncoveredAdvisories', () => {
  const accepted = new Set(['GHSA-3JXR-9VMJ-R5CP', 'CVE-2026-13149']);

  it('is empty when every advisory GHSA is in the accepted set', () => {
    const doc = auditDoc({
      'brace-expansion': advisory(
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
      ),
    });
    expect(uncoveredAdvisories(doc, accepted)).toEqual([]);
  });
  it('lists the package name of an advisory NOT covered by any record', () => {
    const doc = auditDoc({
      tar: advisory('https://github.com/advisories/GHSA-w8wr-v893-vjvp'),
    });
    expect(uncoveredAdvisories(doc, accepted)).toEqual(['tar']);
  });
  it('treats an advisory with NO extractable GHSA as uncovered (fail-closed)', () => {
    const doc = auditDoc({ mystery: advisory('https://example.com/no-ghsa') });
    expect(uncoveredAdvisories(doc, accepted)).toEqual(['mystery']);
  });
  it('returns a sorted, deduped list across many packages', () => {
    const doc = auditDoc({
      zeta: advisory('https://example.com/x'),
      alpha: advisory('https://example.com/y'),
    });
    expect(uncoveredAdvisories(doc, accepted)).toEqual(['alpha', 'zeta']);
  });
  it('covers via ANY of an advisory’s GHSAs (one accepted is enough)', () => {
    const doc = auditDoc({
      multi: advisory(
        'https://github.com/advisories/GHSA-zzzz-zzzz-zzzz',
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
      ),
    });
    expect(uncoveredAdvisories(doc, accepted)).toEqual([]);
  });
  it('is total: malformed audit JSON yields [] (no vulnerabilities to gate)', () => {
    expect(uncoveredAdvisories(undefined, accepted)).toEqual([]);
    expect(uncoveredAdvisories('x', accepted)).toEqual([]);
    expect(uncoveredAdvisories({}, accepted)).toEqual([]);
    expect(uncoveredAdvisories({ vulnerabilities: 42 }, accepted)).toEqual([]);
  });
  it('is empty when there are no vulnerabilities at all (clean audit)', () => {
    expect(uncoveredAdvisories(auditDoc({}), accepted)).toEqual([]);
  });
});

describe('coveredAdvisories', () => {
  const accepted = new Set(['GHSA-3JXR-9VMJ-R5CP']);

  it('reports package → the covered GHSA ids (the transparency signal)', () => {
    const doc = auditDoc({
      'brace-expansion': advisory(
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
      ),
    });
    expect(coveredAdvisories(doc, accepted)).toEqual([
      { pkg: 'brace-expansion', ids: ['GHSA-3JXR-9VMJ-R5CP'] },
    ]);
  });
  it('omits advisories with no covered GHSA', () => {
    const doc = auditDoc({ tar: advisory('https://example.com/x') });
    expect(coveredAdvisories(doc, accepted)).toEqual([]);
  });
  it('lists only the covered subset of an advisory’s GHSAs, sorted', () => {
    const doc = auditDoc({
      'brace-expansion': advisory(
        'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
        'https://github.com/advisories/GHSA-zzzz-zzzz-zzzz',
      ),
    });
    expect(coveredAdvisories(doc, accepted)).toEqual([
      { pkg: 'brace-expansion', ids: ['GHSA-3JXR-9VMJ-R5CP'] },
    ]);
  });
  it('returns each advisory’s covered ids in SORTED order', () => {
    // Two covered GHSAs supplied out of order — proves the `.sort()` on the id
    // list (not just insertion order) is load-bearing.
    // Accepted ids are normalized (upper-case) by the shared ledger's normId,
    // so the set is upper-case here too.
    const multiAccepted = new Set([
      'GHSA-FFFF-FFFF-FFFF',
      'GHSA-AAAA-AAAA-AAAA',
    ]);
    const doc = auditDoc({
      pkg: advisory(
        'https://github.com/advisories/GHSA-ffff-ffff-ffff',
        'https://github.com/advisories/GHSA-aaaa-aaaa-aaaa',
      ),
    });
    expect(coveredAdvisories(doc, multiAccepted)).toEqual([
      { pkg: 'pkg', ids: ['GHSA-AAAA-AAAA-AAAA', 'GHSA-FFFF-FFFF-FFFF'] },
    ]);
  });
  it('is total on malformed input', () => {
    expect(coveredAdvisories(undefined, accepted)).toEqual([]);
    expect(coveredAdvisories({ vulnerabilities: 'x' }, accepted)).toEqual([]);
  });
});

describe('resolveNow', () => {
  it('parses an ISO date string to a UTC-midnight Date', () => {
    expect(resolveNow('2026-07-22').toISOString()).toBe(
      '2026-07-22T00:00:00.000Z',
    );
  });
  it('returns the epoch for an empty/absent arg (no record ever overdue)', () => {
    // Local ad-hoc runs omit the date; the epoch makes every dated record
    // still-active (nothing is on/before 1970), the safe default.
    expect(resolveNow('').getTime()).toBe(0);
    expect(resolveNow(undefined).getTime()).toBe(0);
  });
});

describe('gateResult', () => {
  // gateResult is the shim's whole DECISION as a pure function: given the parsed
  // audit JSON + the raw vex docs + now, return the outcome + the lines to
  // print. The .mjs shim only does read/parse/write/exit around this.
  const auditWith = (ghsa: string) =>
    auditDoc({
      'brace-expansion': advisory(`https://github.com/advisories/${ghsa}`),
    });
  const vexDoc = (revisit_by?: string) => ({
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-13149',
          aliases: ['GHSA-3jxr-9vmj-r5cp'],
        },
        status: 'affected',
      },
    ],
    ...(revisit_by === undefined ? {} : { revisit_by }),
  });
  const now = new Date('2026-07-22T00:00:00.000Z');

  it('fails closed when the audit JSON is undefined (unreadable)', () => {
    const r = gateResult(undefined, [vexDoc()], now);
    expect(r.outcome).toBe('failure');
    expect(r.failedClosed).toBe(true);
    expect(r.uncovered).toEqual([]);
    expect(r.covered).toEqual([]);
  });
  it('passes when the sole advisory is covered by an active record', () => {
    const r = gateResult(
      auditWith('GHSA-3jxr-9vmj-r5cp'),
      [vexDoc('2026-10-01')],
      now,
    );
    expect(r.outcome).toBe('success');
    expect(r.failedClosed).toBe(false);
    expect(r.uncovered).toEqual([]);
    expect(r.covered).toEqual([
      { pkg: 'brace-expansion', ids: ['GHSA-3JXR-9VMJ-R5CP'] },
    ]);
  });
  it('fails when the advisory is uncovered (no record)', () => {
    const r = gateResult(auditWith('GHSA-3jxr-9vmj-r5cp'), [], now);
    expect(r.outcome).toBe('failure');
    expect(r.failedClosed).toBe(false);
    expect(r.uncovered).toEqual(['brace-expansion']);
    expect(r.covered).toEqual([]);
  });
  it('fails (self-reds) when the covering record’s dated revisit_by is overdue', () => {
    const r = gateResult(
      auditWith('GHSA-3jxr-9vmj-r5cp'),
      [vexDoc('2026-01-01')],
      now,
    );
    expect(r.outcome).toBe('failure');
    expect(r.uncovered).toEqual(['brace-expansion']);
    // still surfaces the (now-inactive) record's non-coverage, not as covered
    expect(r.covered).toEqual([]);
  });
  it('reports acceptedCount = size of the active accepted-id set', () => {
    const r = gateResult(auditWith('GHSA-3jxr-9vmj-r5cp'), [vexDoc()], now);
    // the record contributes CVE-2026-13149 + GHSA-3JXR-9VMJ-R5CP
    expect(r.acceptedCount).toBe(2);
  });
});

// Integration with the shared ledger's dated-expiry: an expired record's ids
// are dropped from the active set, so a previously-covered advisory re-reds.
describe('npm-audit-gate × activeRecordIds (dated-expiry self-red)', () => {
  const today = new Date('2026-07-22T12:00:00.000Z');
  const doc = auditDoc({
    'brace-expansion': advisory(
      'https://github.com/advisories/GHSA-3jxr-9vmj-r5cp',
    ),
  });
  const vexDoc = (revisit_by?: string) => ({
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-13149',
          aliases: ['GHSA-3jxr-9vmj-r5cp'],
        },
        status: 'affected',
      },
    ],
    ...(revisit_by === undefined ? {} : { revisit_by }),
  });

  it('PASSES while the dated revisit_by is in the future', () => {
    const accepted = activeRecordIds([vexDoc('2026-10-01')], today);
    expect(uncoveredAdvisories(doc, accepted)).toEqual([]);
  });
  it('RE-REDS once the dated revisit_by is overdue', () => {
    const accepted = activeRecordIds([vexDoc('2026-01-01')], today);
    expect(uncoveredAdvisories(doc, accepted)).toEqual(['brace-expansion']);
  });
});
