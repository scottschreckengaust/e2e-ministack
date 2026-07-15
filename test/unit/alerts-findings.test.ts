import {
  idFromRule,
  badgeSeverity,
  parseAlerts,
  filterByCategory,
  mergeAlertLedgers,
  toScannerFindings,
  asRecord,
  asArray,
  str,
  type AlertFinding,
} from '../../.github/scripts/alerts-findings';

// Unit tests for .github/scripts/alerts-findings.ts (#189 CI wiring): normalize
// the GitHub Code Scanning Alerts API response into the finding shape the VEX
// report reconciles against `.vex/`. In-process import so it flows through the
// 100% coverage gate (#124) + Stryker mutation (#122, zero survivors). Its
// output feeds the per-push report — a wrong mapping mis-states the two-ledger
// reconciliation, so correctness matters.

describe('idFromRule', () => {
  it('extracts the CVE token from a grype/trivy rule id, upper-cased', () => {
    expect(idFromRule('CVE-2026-11822-libsqlite3-0')).toBe('CVE-2026-11822'); // grype
    expect(idFromRule('CVE-2026-11822')).toBe('CVE-2026-11822'); // trivy
    expect(idFromRule('cve-2026-1-x')).toBe('CVE-2026-1');
  });
  it('keeps a non-CVE rule id verbatim (e.g. SonarQube), so the report can filter it', () => {
    expect(idFromRule('typescript:S1848')).toBe('typescript:S1848');
    expect(idFromRule('TEMP-0290435-0B57B5')).toBe('TEMP-0290435-0B57B5');
  });
  it('returns "" for a missing/non-string rule id', () => {
    expect(idFromRule(undefined)).toBe('');
    expect(idFromRule(null)).toBe('');
    expect(idFromRule(42)).toBe('');
  });
});

describe('badgeSeverity', () => {
  it('uppercases a known severity keyword', () => {
    expect(badgeSeverity('high')).toBe('HIGH');
    expect(badgeSeverity('Critical')).toBe('CRITICAL');
    expect(badgeSeverity('MEDIUM')).toBe('MEDIUM');
    expect(badgeSeverity('low')).toBe('LOW');
  });
  it('maps null/unknown/garbage to UNKNOWN', () => {
    expect(badgeSeverity(null)).toBe('UNKNOWN'); // GitHub uses null when unscored
    expect(badgeSeverity(undefined)).toBe('UNKNOWN');
    expect(badgeSeverity('bogus')).toBe('UNKNOWN');
    expect(badgeSeverity(9.8)).toBe('UNKNOWN'); // it's a keyword field, not a number
  });
});

describe('parseAlerts', () => {
  const alert = (over: Record<string, unknown>) => ({
    number: 1,
    state: 'open',
    rule: { id: 'CVE-2026-1-libnode115', security_severity_level: 'high' },
    tool: { name: 'Grype' },
    most_recent_instance: { category: 'grype-ministack-image' },
    html_url: 'https://example.test/alert/1',
    ...over,
  });

  it('maps a full alert to {id, scanner, badgeSeverity, state, dismissedReason, category, htmlUrl, fixedAt}', () => {
    const out = parseAlerts([alert({})]);
    expect(out).toEqual([
      {
        id: 'CVE-2026-1',
        scanner: 'Grype',
        badgeSeverity: 'HIGH',
        state: 'open',
        dismissedReason: '',
        category: 'grype-ministack-image',
        htmlUrl: 'https://example.test/alert/1',
        fixedAt: '', // not fixed => empty
      },
    ]);
  });

  it('captures fixed_at when the alert is fixed (bounds the recently-resolved window)', () => {
    const out = parseAlerts([
      alert({ state: 'fixed', fixed_at: '2026-07-15T20:08:43Z' }),
    ]);
    expect(out[0].state).toBe('fixed');
    expect(out[0].fixedAt).toBe('2026-07-15T20:08:43Z');
  });

  it('preserves dismissed state + reason (the second-ledger signal)', () => {
    const out = parseAlerts([
      alert({ state: 'dismissed', dismissed_reason: "won't fix" }),
    ]);
    expect(out[0].state).toBe('dismissed');
    expect(out[0].dismissedReason).toBe("won't fix");
  });

  it('skips an alert whose rule id is missing/empty', () => {
    const out = parseAlerts([
      { state: 'open', rule: {}, tool: { name: 'Grype' } }, // no rule.id
      alert({}),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe('CVE-2026-1');
  });

  it('defaults missing tool/severity/category/html_url to safe empties', () => {
    const out = parseAlerts([{ state: 'open', rule: { id: 'CVE-2026-9' } }]);
    expect(out[0]).toEqual({
      id: 'CVE-2026-9',
      scanner: '',
      badgeSeverity: 'UNKNOWN',
      state: 'open',
      dismissedReason: '',
      category: '',
      htmlUrl: '',
      fixedAt: '',
    });
  });

  it('captures the alert html_url (for the report scanner links)', () => {
    const out = parseAlerts([
      alert({ html_url: 'https://github.com/o/r/security/code-scanning/42' }),
    ]);
    expect(out[0].htmlUrl).toBe(
      'https://github.com/o/r/security/code-scanning/42',
    );
  });

  it('tolerates missing/garbage input without throwing (totality)', () => {
    expect(parseAlerts(undefined)).toEqual([]);
    expect(parseAlerts(null)).toEqual([]);
    expect(parseAlerts('x')).toEqual([]);
    expect(parseAlerts({})).toEqual([]); // not an array
    expect(parseAlerts([null, 7, 'x'])).toEqual([]); // junk elements skipped
    expect(parseAlerts([{ rule: 'notrecord' }])).toEqual([]); // rule not a record
  });
});

describe('filterByCategory', () => {
  const f = (id: string, category: string): AlertFinding => ({
    id,
    scanner: 'Grype',
    badgeSeverity: 'HIGH',
    state: 'open',
    dismissedReason: '',
    category,
    htmlUrl: '',
    fixedAt: '',
  });

  it('keeps only findings in the requested categories', () => {
    const out = filterByCategory(
      [
        f('CVE-1', 'grype-ministack-image'),
        f('S1848', 'sonarqube'),
        f('CVE-2', 'trivy-image'),
      ],
      ['grype-ministack-image', 'trivy-image'],
    );
    expect(out.map((x) => x.id)).toEqual(['CVE-1', 'CVE-2']); // sonarqube dropped
  });

  it('keeps everything when no categories are given', () => {
    const all = [f('CVE-1', 'grype-ministack-image'), f('S1848', 'sonarqube')];
    expect(filterByCategory(all, [])).toEqual(all);
  });
});

describe('mergeAlertLedgers (run-ref open + main-ref fixed/dismissed history)', () => {
  const fa = (
    id: string,
    scanner: string,
    state: string,
    over: Partial<AlertFinding> = {},
  ): AlertFinding => ({
    id,
    scanner,
    badgeSeverity: 'HIGH',
    state,
    dismissedReason: '',
    category: 'grype-ministack-image',
    htmlUrl: '',
    fixedAt: '',
    ...over,
  });

  it('adds main-only findings (the fixed/dismissed history the run ref lacks)', () => {
    const run = [fa('CVE-1', 'Grype', 'open')];
    const main = [
      fa('CVE-1', 'Grype', 'dismissed'), // dup key — run wins, NOT added
      fa('CVE-2', 'Grype', 'fixed', { fixedAt: '2026-07-15' }), // main-only — added
    ];
    const out = mergeAlertLedgers(run, main);
    expect(out.map((x) => [x.id, x.state])).toEqual([
      ['CVE-1', 'open'], // run-ref entry wins for the shared key
      ['CVE-2', 'fixed'], // main-only resolved history brought in
    ]);
  });

  it('keys by id AND scanner (same CVE from two scanners are distinct)', () => {
    const run = [fa('CVE-1', 'Grype', 'open')];
    const main = [fa('CVE-1', 'Trivy', 'fixed', { fixedAt: '2026-07-15' })];
    const out = mergeAlertLedgers(run, main);
    // different scanner => different key => both kept
    expect(out.map((x) => [x.id, x.scanner])).toEqual([
      ['CVE-1', 'Grype'],
      ['CVE-1', 'Trivy'],
    ]);
  });

  it('run-ref entries lead, in order; main-only appended after', () => {
    const run = [fa('CVE-B', 'Grype', 'open'), fa('CVE-A', 'Grype', 'open')];
    const main = [fa('CVE-C', 'Grype', 'fixed')];
    expect(mergeAlertLedgers(run, main).map((x) => x.id)).toEqual([
      'CVE-B',
      'CVE-A',
      'CVE-C',
    ]);
  });

  it('empty main => run unchanged; empty run => main passthrough', () => {
    const run = [fa('CVE-1', 'Grype', 'open')];
    expect(mergeAlertLedgers(run, [])).toEqual(run);
    const main = [fa('CVE-2', 'Grype', 'fixed')];
    expect(mergeAlertLedgers([], main)).toEqual(main);
  });
});

describe('toScannerFindings (the AlertFinding -> ScannerFinding seam)', () => {
  const af = (over: Partial<AlertFinding> = {}): AlertFinding => ({
    id: 'CVE-2026-1',
    scanner: 'Grype',
    badgeSeverity: 'CRITICAL',
    state: 'open',
    dismissedReason: '',
    category: 'grype-ministack-image',
    htmlUrl: 'https://x.test/1',
    fixedAt: '',
    ...over,
  });

  it('maps badgeSeverity -> severity and carries id/scanner/state/htmlUrl/fixedAt', () => {
    // This is the load-bearing rename: the report reads `severity`, the alert
    // exposes `badgeSeverity`. A wrong mapping makes every CI severity UNKNOWN.
    expect(
      toScannerFindings([af({ fixedAt: '2026-07-15T00:00:00Z' })]),
    ).toEqual([
      {
        id: 'CVE-2026-1',
        scanner: 'Grype',
        severity: 'CRITICAL',
        state: 'open',
        htmlUrl: 'https://x.test/1',
        fixedAt: '2026-07-15T00:00:00Z',
      },
    ]);
  });

  it('preserves per-finding values across a multi-element map', () => {
    const out = toScannerFindings([
      af({ id: 'CVE-2026-1', scanner: 'Grype', badgeSeverity: 'HIGH' }),
      af({
        id: 'CVE-2026-2',
        scanner: 'Trivy',
        badgeSeverity: 'MEDIUM',
        state: 'dismissed',
        htmlUrl: 'https://x.test/2',
      }),
    ]);
    expect(out).toEqual([
      {
        id: 'CVE-2026-1',
        scanner: 'Grype',
        severity: 'HIGH',
        state: 'open',
        htmlUrl: 'https://x.test/1',
        fixedAt: '',
      },
      {
        id: 'CVE-2026-2',
        scanner: 'Trivy',
        severity: 'MEDIUM',
        state: 'dismissed',
        htmlUrl: 'https://x.test/2',
        fixedAt: '',
      },
    ]);
  });

  it('returns [] for an empty input', () => {
    expect(toScannerFindings([])).toEqual([]);
  });
});

describe('coercion helpers (tested directly — every branch observable)', () => {
  it('asRecord: object passes; array/null/primitive => null', () => {
    const o = { a: 1 };
    expect(asRecord(o)).toBe(o);
    expect(asRecord([1])).toBeNull();
    expect(asRecord(null)).toBeNull();
    expect(asRecord('x')).toBeNull();
    expect(asRecord(3)).toBeNull();
  });
  it('asArray: array passes; else []', () => {
    const a = [1];
    expect(asArray(a)).toBe(a);
    expect(asArray('x')).toEqual([]);
    expect(asArray(null)).toEqual([]);
    expect(asArray({})).toEqual([]);
  });
  it('str: string passes; else ""', () => {
    expect(str('hi')).toBe('hi');
    expect(str('')).toBe('');
    expect(str(1)).toBe('');
    expect(str(null)).toBe('');
    expect(str(['x'])).toBe('');
  });
});
