import {
  isCveId,
  isoDayNumber,
  isRevisitOverdue,
  isActionable,
  suggestJustification,
  buildReport,
  summarize,
  renderMarkdown,
  type VexRecord,
  type ScannerFinding,
  type UnifiedStatus,
} from '../../.github/scripts/vex-report';

// Unit tests for .github/scripts/vex-report.ts (#189): reconcile committed
// `.vex/` records against scanner findings into a review-friendly report.
// Imported in-process so it flows through the 100% coverage gate (#124) +
// Stryker mutation (#122). The report is what a PR reviewer reads to know
// whether any accepted risk needs re-examination, so its correctness matters.

const NOT_AFFECTED = 'vulnerable_code_cannot_be_controlled_by_adversary';

function finding(
  id: string,
  scanner: string,
  severity: string,
  pkg?: string,
): ScannerFinding {
  return { id, scanner, severity, pkg };
}

describe('isCveId', () => {
  it('accepts a well-formed CVE id (any case)', () => {
    expect(isCveId('CVE-2026-11822')).toBe(true);
    expect(isCveId('cve-2026-1')).toBe(true);
  });
  it('rejects TEMP-/GHSA pseudo-ids and non-strings', () => {
    expect(isCveId('TEMP-0290435-0B57B5')).toBe(false);
    expect(isCveId('GHSA-xxxx-yyyy-zzzz')).toBe(false);
    expect(isCveId('CVE-2026')).toBe(false); // missing the sequence
    expect(isCveId('xCVE-2026-1')).toBe(false); // anchored — no prefix
    expect(isCveId('CVE-2026-1x')).toBe(false); // anchored — no suffix
    expect(isCveId(42)).toBe(false);
    expect(isCveId(undefined)).toBe(false);
  });
  it('rejects a non-string that STRINGIFIES to a CVE (the typeof guard is load-bearing)', () => {
    // `String(['CVE-2026-1']) === 'CVE-2026-1'`, so without the typeof guard
    // `CVE_RE.test` would coerce and falsely match. It must be false.
    expect(isCveId(['CVE-2026-1'])).toBe(false);
    expect(isCveId({ toString: () => 'CVE-2026-1' })).toBe(false);
  });
});

describe('isoDayNumber', () => {
  it('encodes the YYYY-MM-DD prefix as a comparable YYYYMMDD integer', () => {
    expect(isoDayNumber('2026-07-14')).toBe(20260714);
    expect(isoDayNumber('2026-07-14T09:30:00Z')).toBe(20260714); // time dropped
    expect(isoDayNumber('2026-12-31T23:59:59.999Z')).toBe(20261231);
  });
  it('orders correctly as integers (later day => larger number)', () => {
    expect(isoDayNumber('2026-07-15')).toBeGreaterThan(
      isoDayNumber('2026-07-14'),
    );
    expect(isoDayNumber('2027-01-01')).toBeGreaterThan(
      isoDayNumber('2026-12-31'),
    );
  });
  it('is NaN for non-date-led strings and absent values', () => {
    expect(isoDayNumber('wait-for-image-rebuild')).toBeNaN();
    expect(isoDayNumber('x2026-07-14')).toBeNaN(); // anchored — must lead
    expect(isoDayNumber('2026-07-1')).toBeNaN(); // day not 2 digits
    expect(isoDayNumber('2026-7-14')).toBeNaN(); // month not 2 digits
    expect(isoDayNumber('')).toBeNaN();
    expect(isoDayNumber(null)).toBeNaN();
    expect(isoDayNumber(undefined)).toBeNaN();
  });
  it('is NaN for a non-string that STRINGIFIES to a date (typeof guard is load-bearing)', () => {
    // `String(['2026-07-14']) === '2026-07-14'` — without the typeof guard the
    // regex would coerce the array and return 20260714. It must be NaN.
    expect(isoDayNumber(['2026-07-14'])).toBeNaN();
  });
});

describe('isActionable', () => {
  it('is true for exactly the three action statuses', () => {
    const all: UnifiedStatus[] = [
      'Accepted',
      'Tracked',
      'Decision needed',
      'Revisit overdue',
      'Stale record',
      'Investigating',
    ];
    const actionable = all.filter(isActionable);
    expect(actionable.sort()).toEqual(
      ['Decision needed', 'Revisit overdue', 'Stale record'].sort(),
    );
  });
});

describe('isRevisitOverdue', () => {
  it('is true only for a DATE on/before today', () => {
    expect(isRevisitOverdue('2026-07-01', '2026-07-14')).toBe(true); // before
    expect(isRevisitOverdue('2026-07-14', '2026-07-14')).toBe(true); // equal (on/before)
    expect(isRevisitOverdue('2026-12-01', '2026-07-14')).toBe(false); // future
  });
  it('is false for an EVENT token (not a date)', () => {
    expect(isRevisitOverdue('wait-for-image-rebuild', '2026-07-14')).toBe(
      false,
    );
  });
  it('is false when EITHER side alone is not a date (kills the ||/null-check mutants)', () => {
    // revisitBy is a date but today is not -> false (guards `now === null`)
    expect(isRevisitOverdue('2026-07-01', 'not-a-date')).toBe(false);
    // today is a date but revisitBy is not -> false (guards `due === null`)
    expect(isRevisitOverdue('wait-for-image-rebuild', '2026-07-14')).toBe(
      false,
    );
    // both absent -> false
    expect(isRevisitOverdue(null, '')).toBe(false);
    // both valid dates, due after now -> false (proves the guard isn't blanket-false)
    expect(isRevisitOverdue('2027-01-01', '2026-07-14')).toBe(false);
  });
  it('compares only the date prefix of an ISO datetime', () => {
    expect(
      isRevisitOverdue('2026-07-14T23:59:59Z', '2026-07-14T00:00:00Z'),
    ).toBe(true);
  });
});

describe('suggestJustification', () => {
  it('returns not_in_execute_path only when EVERY package is a never-run tool', () => {
    expect(suggestJustification(['mount', 'tar'])).toBe(
      'vulnerable_code_not_in_execute_path',
    );
    expect(suggestJustification(['bsdutils'])).toBe(
      'vulnerable_code_not_in_execute_path',
    );
  });
  it('falls back to cannot_be_controlled when any package is a linked lib', () => {
    expect(suggestJustification(['node-undici'])).toBe(NOT_AFFECTED);
    // mixed: a never-run tool AND a lib -> not the tighter enum
    expect(suggestJustification(['mount', 'node-undici'])).toBe(NOT_AFFECTED);
  });
  it('defaults to cannot_be_controlled for empty/unknown packages', () => {
    expect(suggestJustification([])).toBe(NOT_AFFECTED);
    expect(suggestJustification(['some-unknown-pkg'])).toBe(NOT_AFFECTED);
  });
});

describe('mutation-hardening — exact values, ordering, regex edges', () => {
  it('maxSeverity uses the correct RANK_NAME label per rank', () => {
    const cases: Array<[string, string]> = [
      ['CRITICAL', 'CRITICAL'],
      ['HIGH', 'HIGH'],
      ['MEDIUM', 'MEDIUM'],
      ['LOW', 'LOW'],
      ['NEGLIGIBLE', 'NEGLIGIBLE'],
      ['UNKNOWN', 'UNKNOWN'],
    ];
    for (const [sev, expected] of cases) {
      const rows = buildReport(
        [],
        [finding(`CVE-2099-${sev}`, 'grype', sev, 'p')],
        'HIGH',
        '2026-07-14',
      );
      expect(rows[0].maxSeverity).toBe(expected);
    }
  });

  it('isRevisitOverdue regex requires a full YYYY-MM-DD prefix (kills length/anchor mutants)', () => {
    expect(isRevisitOverdue('2026-07-1', '2026-07-14')).toBe(false); // day not 2 digits
    expect(isRevisitOverdue('x2026-07-14', '2026-07-14')).toBe(false); // not anchored at start
    expect(isRevisitOverdue('2026-07-14', '2026-07-1')).toBe(false); // today malformed
  });

  it('skips a vex record with a blank/missing cve (kills the loop-guard mutant)', () => {
    // A record with an empty cve must NOT be indexed — otherwise it would shadow
    // or mis-key. With the guard removed, an empty-cve record would be added and
    // (having no finding) surface as an extra Stale row.
    const rows = buildReport(
      [
        { cve: '', status: 'not_affected', justification: 'x' },
        { cve: 'CVE-2099-1', status: 'not_affected', justification: 'x' },
      ],
      [finding('CVE-2099-1', 'grype', 'HIGH', 'p')],
      'HIGH',
      '2026-07-14',
    );
    // Only the real CVE row exists (Accepted); the blank-cve record is dropped.
    expect(rows).toHaveLength(1);
    expect(rows[0].item).toBe('CVE-2099-1');
  });

  it('skips a finding with a blank/missing id (kills the finding-guard mutant)', () => {
    const rows = buildReport(
      [],
      [
        { id: '', scanner: 'grype', severity: 'HIGH' },
        finding('CVE-2099-2', 'grype', 'HIGH', 'p'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].item).toBe('CVE-2099-2');
  });

  it('ignores a non-string or empty scanner/pkg (nonEmptyString guard is observable)', () => {
    const rows = buildReport(
      [],
      [
        // truthy NON-string scanner + pkg must NOT become a tool/package label
        {
          id: 'CVE-2099-3',
          scanner: 42 as unknown as string,
          severity: 'HIGH',
          pkg: 7 as unknown as string,
        },
        // empty-string scanner/pkg must also be excluded
        { id: 'CVE-2099-3', scanner: '', severity: 'HIGH', pkg: '' },
        // a real one to prove the row still forms
        finding('CVE-2099-3', 'grype', 'HIGH', 'openssl'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].tools).toEqual(['grype']); // 42 and '' excluded
    expect(rows[0].packages).toEqual(['openssl']); // 7 and '' excluded
  });

  it('overdue compares only date parts even when today carries a time suffix', () => {
    // revisitBy date == today date but today has a later time -> still overdue
    // (kills the mutant that drops today.slice(0,10)).
    expect(isRevisitOverdue('2026-07-14', '2026-07-14T09:00:00Z')).toBe(true);
  });

  it('the comparator returns 0 for equal severity so items tie-break by name', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-B', 'grype', 'HIGH', 'p'),
        finding('CVE-2099-A', 'grype', 'HIGH', 'p'),
      ],
      'HIGH',
      '2026-07-14',
    );
    // equal severity => localeCompare by item ascending
    expect(rows.map((r) => r.item)).toEqual(['CVE-2099-A', 'CVE-2099-B']);
  });

  it('severities/tools are sorted deterministically by scanner name', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-1', 'trivy', 'HIGH', 'zzz'),
        finding('CVE-2099-1', 'grype', 'HIGH', 'aaa'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].tools).toEqual(['grype', 'trivy']); // sorted, not insertion order
    expect(rows[0].packages).toEqual(['aaa', 'zzz']); // sorted
  });

  it('non-string severity becomes exactly "UNKNOWN" (kills the literal mutant)', () => {
    const rows = buildReport(
      [],
      [{ id: 'CVE-2099-X', scanner: 'g', severity: 42 as unknown as string }],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].severities.g).toBe('UNKNOWN');
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('a stale record row has maxSeverity exactly "UNKNOWN"', () => {
    const rows = buildReport(
      [{ cve: 'CVE-2099-Y', status: 'not_affected', justification: 'x' }],
      [],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('a row with no packages renders an em-dash in the package column', () => {
    // stale record has empty packages -> "—" (kills the pkgs join literal mutant)
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2099-3', status: 'not_affected', justification: 'x' }],
        [],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('| CVE-2099-3 | Stale record | x | — | — | — | 🔴 |');
  });

  it('the investigating summary suffix text is exact', () => {
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2099-I', status: 'under_investigation' }],
        [finding('CVE-2099-I', 'grype', 'HIGH', 'p')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain(' · 1 investigating');
  });

  it('omits the investigating suffix ENTIRELY when count is 0 (exact summary line)', () => {
    // Kills the else-branch mutant: with 0 investigating, the summary must end
    // after "tracked" with NO extra suffix appended.
    const md = renderMarkdown(
      buildReport(
        [],
        [finding('CVE-2099-T', 'grype', 'LOW', 'zlib1g')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md.split('\n')[0]).toBe(
      '**VEX report** — 1 item(s): 0 decision needed · 0 vex drift · 0 undocumented dismissal · 0 revisit overdue · 0 stale · 0 accepted · 1 tracked',
    );
  });

  it('a clean row has an empty signal string (kills the ||-fallback mutant)', () => {
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2026-1', status: 'not_affected', justification: 'x' }],
        [finding('CVE-2026-1', 'grype', 'HIGH', 'p')],
        'HIGH',
        '2026-07-14',
      ),
    );
    // The accepted row's ledger line ends "| x | grype=HIGH | — |  |" — empty signal.
    expect(md).toContain(
      '| CVE-2026-1 | Accepted | x | p | grype=HIGH | — |  |',
    );
  });
});

describe('buildReport — status mapping', () => {
  const vex = (over: Partial<VexRecord> & { cve: string }): VexRecord => ({
    status: 'not_affected',
    justification: NOT_AFFECTED,
    ...over,
  });

  it('not_affected/fixed with a finding => Accepted', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-1' }), vex({ cve: 'CVE-2026-2', status: 'fixed' })],
      [
        finding('CVE-2026-1', 'grype', 'HIGH'),
        finding('CVE-2026-2', 'trivy', 'HIGH'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows.every((r) => r.status === 'Accepted')).toBe(true);
    expect(rows.every((r) => r.actionNeeded === false)).toBe(true);
  });

  it('affected with a finding => Tracked (Option A: visible, not dismissed)', () => {
    const rows = buildReport(
      [
        vex({
          cve: 'CVE-2026-3',
          status: 'affected',
          justification: undefined,
        }),
      ],
      [finding('CVE-2026-3', 'grype', 'MEDIUM')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Tracked');
    expect(rows[0].actionNeeded).toBe(false);
  });

  it('under_investigation => Investigating', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-4', status: 'under_investigation' })],
      [finding('CVE-2026-4', 'grype', 'HIGH')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Investigating');
  });

  it('uncovered at/above floor => Decision needed (action)', () => {
    const rows = buildReport(
      [],
      [finding('CVE-2099-1', 'trivy', 'CRITICAL', 'openssl')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Decision needed');
    expect(rows[0].actionNeeded).toBe(true);
    expect(rows[0].suggestedJustification).toBe(NOT_AFFECTED);
  });

  it('uncovered below floor => Tracked (no action)', () => {
    const rows = buildReport(
      [],
      [finding('CVE-2099-2', 'trivy', 'LOW', 'zlib1g')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Tracked');
    expect(rows[0].actionNeeded).toBe(false);
  });

  it('uncovered EXACTLY AT the floor => Decision needed (kills >= vs > mutant)', () => {
    // A HIGH finding with floor HIGH must block (>=, not >). If it were `>`,
    // an at-floor finding would slip to Tracked — this pins the boundary.
    const rows = buildReport(
      [],
      [finding('CVE-2099-AT', 'grype', 'HIGH', 'openssl')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Decision needed');
  });

  it('accepted record past its revisit DATE => Revisit overdue (action)', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-5', revisitBy: '2026-01-01' })],
      [finding('CVE-2026-5', 'grype', 'HIGH')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Revisit overdue');
    expect(rows[0].revisitOverdue).toBe(true);
    expect(rows[0].actionNeeded).toBe(true);
  });

  it('affected record past its revisit DATE also => Revisit overdue', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-6', status: 'affected', revisitBy: '2026-01-01' })],
      [finding('CVE-2026-6', 'grype', 'MEDIUM')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Revisit overdue');
  });

  it('event-token revisit_by never goes overdue', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-7', revisitBy: 'wait-for-image-rebuild' })],
      [finding('CVE-2026-7', 'grype', 'HIGH')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Accepted');
    expect(rows[0].revisitOverdue).toBe(false);
    expect(rows[0].revisitBy).toBe('wait-for-image-rebuild');
  });

  it('a VEX record with no matching finding => Stale record (action)', () => {
    const rows = buildReport(
      [vex({ cve: 'CVE-2026-8', revisitBy: '2026-01-01' })],
      [], // no finding
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].actionNeeded).toBe(true);
    expect(rows[0].revisitOverdue).toBe(true);
    expect(rows[0].tools).toEqual([]);
    expect(rows[0].packages).toEqual([]);
  });

  it('a stale record with NO justification yields null (guards the ?? on the stale path)', () => {
    const rows = buildReport(
      [{ cve: 'CVE-2026-88', status: 'not_affected' }], // no justification, no finding
      [],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].suggestedJustification).toBeNull();
  });

  it('a stale record PRESERVES its revisit_by (kills the ?? -> && mutant on the stale path)', () => {
    const rows = buildReport(
      [
        {
          cve: 'CVE-2026-89',
          status: 'not_affected',
          justification: 'x',
          revisitBy: '2026-01-01',
        },
      ],
      [], // no finding => stale
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].revisitBy).toBe('2026-01-01'); // not null-ed by a && mutant
  });
});

describe('buildReport — two-ledger reconciliation (alert state)', () => {
  const na = (cve: string): VexRecord => ({
    cve,
    status: 'not_affected',
    justification: NOT_AFFECTED,
  });

  it('not_affected + alert DISMISSED => Accepted (the steady state)', () => {
    const rows = buildReport(
      [na('CVE-2026-1')],
      [
        {
          id: 'CVE-2026-1',
          scanner: 'Grype',
          severity: 'HIGH',
          state: 'dismissed',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Accepted');
    expect(rows[0].actionNeeded).toBe(false);
  });

  it('not_affected + alert still OPEN => VEX drift (action)', () => {
    const rows = buildReport(
      [na('CVE-2026-2')],
      [{ id: 'CVE-2026-2', scanner: 'Grype', severity: 'HIGH', state: 'open' }],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('VEX drift');
    expect(rows[0].actionNeeded).toBe(true);
  });

  it('one dismissed + one OPEN alert for a covered CVE => VEX drift (any-open wins)', () => {
    const rows = buildReport(
      [na('CVE-2026-3')],
      [
        {
          id: 'CVE-2026-3',
          scanner: 'Grype',
          severity: 'HIGH',
          state: 'dismissed',
        },
        { id: 'CVE-2026-3', scanner: 'Trivy', severity: 'HIGH', state: 'open' },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('VEX drift');
  });

  it('no VEX + alert DISMISSED => Undocumented dismissal (inverse drift, action)', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-9',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'dismissed',
          pkg: 'zlib1g',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Undocumented dismissal');
    expect(rows[0].actionNeeded).toBe(true);
  });

  it('no VEX + alert FIXED (finding gone) => Resolved, NOT actionable', () => {
    // A `fixed` alert auto-closed because the finding disappeared — NOT a human
    // dismissal to justify. Must be Resolved (informational), not Undocumented
    // dismissal, and must not raise the 🔴 signal.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-10',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'fixed',
          pkg: 'zlib1g',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Resolved');
    expect(rows[0].actionNeeded).toBe(false);
  });

  it('no VEX + BOTH a dismissed and a fixed alert (none open) => Undocumented dismissal wins', () => {
    // Dismissed (human) takes precedence over fixed — the human action is the
    // one that needs documentation.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-13',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'fixed',
          pkg: 'zlib1g',
        },
        {
          id: 'CVE-2099-13',
          scanner: 'Trivy',
          severity: 'LOW',
          state: 'dismissed',
          pkg: 'zlib1g',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Undocumented dismissal');
  });

  it('undocumented-dismissal suggests justification FROM its packages (kills the []-spread mutant)', () => {
    // A never-run package (tar) must yield not-in-execute-path, not the default
    // — proving the pkgs are actually passed to suggestJustification here.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-12',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'dismissed',
          pkg: 'tar',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Undocumented dismissal');
    expect(rows[0].suggestedJustification).toBe(
      'vulnerable_code_not_in_execute_path',
    );
  });

  it('no VEX + a dismissed AND an open alert => NOT undocumented (an open one still needs the decision)', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-11',
          scanner: 'Grype',
          severity: 'CRITICAL',
          state: 'dismissed',
          pkg: 'openssl',
        },
        {
          id: 'CVE-2099-11',
          scanner: 'Trivy',
          severity: 'CRITICAL',
          state: 'open',
          pkg: 'openssl',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    // anyOpen is true, so the undocumented-dismissal branch is skipped; the
    // open critical is a live decision.
    expect(rows[0].status).toBe('Decision needed');
  });

  it('absent state leaves the pure .vex/ verdict unchanged (no ledger opinion)', () => {
    // A not_affected record with a finding that has NO state must stay Accepted
    // (not flip to VEX drift) — drift needs POSITIVE open evidence.
    const rows = buildReport(
      [na('CVE-2026-4')],
      [{ id: 'CVE-2026-4', scanner: 'Grype', severity: 'HIGH' }], // no state
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Accepted');
  });

  it('uncovered + OPEN alert below the floor => Tracked (open branch, below-floor side)', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-19',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'open',
          pkg: 'zlib1g',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Tracked');
  });

  it('uncovered + OPEN alert EXACTLY AT the floor => Decision needed (kills >= vs >), justification from pkgs', () => {
    // never-run pkg (tar) => not-in-execute-path, which also proves the
    // uncovered-open branch passes its packages to suggestJustification
    // (kills the []-spread mutant there).
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-18',
          scanner: 'Grype',
          severity: 'HIGH',
          state: 'open',
          pkg: 'tar',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Decision needed');
    expect(rows[0].suggestedJustification).toBe(
      'vulnerable_code_not_in_execute_path',
    );
  });

  it('undocumented-dismissal + resolved suggest justification FROM packages (kill []-spread mutants)', () => {
    const dismissed = buildReport(
      [],
      [
        {
          id: 'CVE-2099-16',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'dismissed',
          pkg: 'tar',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(dismissed[0].status).toBe('Undocumented dismissal');
    expect(dismissed[0].suggestedJustification).toBe(
      'vulnerable_code_not_in_execute_path',
    );
    const resolved = buildReport(
      [],
      [
        {
          id: 'CVE-2099-17',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'fixed',
          pkg: 'tar',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(resolved[0].status).toBe('Resolved');
    expect(resolved[0].suggestedJustification).toBe(
      'vulnerable_code_not_in_execute_path',
    );
  });

  it('uncovered finding with NO alert state falls to pure severity (no ledger opinion)', () => {
    // state absent => not open/dismissed/fixed => the severity path decides.
    const belowFloor = buildReport(
      [],
      [{ id: 'CVE-2099-20', scanner: 'Grype', severity: 'LOW', pkg: 'zlib1g' }],
      'HIGH',
      '2026-07-14',
    );
    expect(belowFloor[0].status).toBe('Tracked');
    const atFloor = buildReport(
      [],
      [
        {
          id: 'CVE-2099-21',
          scanner: 'Grype',
          severity: 'HIGH',
          pkg: 'openssl',
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(atFloor[0].status).toBe('Decision needed');
  });

  it('renders a "resolved" suffix in the summary when present', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [
          {
            id: 'CVE-2099-22',
            scanner: 'Grype',
            severity: 'LOW',
            state: 'fixed',
            pkg: 'zlib1g',
          },
        ],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain(' · 1 resolved');
    // Resolved is NOT actionable, so the clean-tree line still shows.
    expect(md).toContain('✅ **No action needed**');
  });

  it('an overdue revisit still wins over VEX-drift (acceptance itself is due)', () => {
    const rows = buildReport(
      [{ ...na('CVE-2026-5'), revisitBy: '2026-01-01' }],
      [{ id: 'CVE-2026-5', scanner: 'Grype', severity: 'HIGH', state: 'open' }],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Revisit overdue');
  });
});

describe('buildReport — merging, severity, ordering', () => {
  it('merges two scanners on one id and records both severities', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-9', 'grype', 'CRITICAL', 'perl-base'),
        finding('CVE-2099-9', 'trivy', 'medium', 'perl-base'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].tools).toEqual(['grype', 'trivy']);
    expect(rows[0].severities).toEqual({ grype: 'CRITICAL', trivy: 'MEDIUM' });
    expect(rows[0].maxSeverity).toBe('CRITICAL'); // union max
  });

  it('normalizes unknown/garbage severity to UNKNOWN', () => {
    const rows = buildReport(
      [],
      [finding('CVE-2099-10', 'grype', 'bogus')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].severities.grype).toBe('UNKNOWN');
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('normalizes a NON-string severity to UNKNOWN (guards the typeof check)', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-11',
          scanner: 'grype',
          severity: 42 as unknown as string,
        },
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].severities.grype).toBe('UNKNOWN');
  });

  it('a not_affected record with NO justification renders an em-dash', () => {
    // Covers the `vex.justification ?? null` fallback on a covered record.
    const rows = buildReport(
      [{ cve: 'CVE-2099-12', status: 'not_affected' }],
      [finding('CVE-2099-12', 'grype', 'HIGH')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].suggestedJustification).toBeNull();
  });

  it('sorts by max severity desc, then item', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-20', 'grype', 'LOW', 'zlib1g'),
        finding('CVE-2099-21', 'grype', 'CRITICAL', 'openssl'),
        finding('CVE-2099-22', 'grype', 'CRITICAL', 'openssl'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows.map((r) => r.item)).toEqual([
      'CVE-2099-21',
      'CVE-2099-22',
      'CVE-2099-20',
    ]);
  });

  it('flags an un-CVE-id item (isCve false)', () => {
    const rows = buildReport(
      [],
      [finding('TEMP-1-ABC', 'trivy', 'LOW', 'tar')],
      'HIGH',
      '2026-07-14',
    );
    expect(rows[0].isCve).toBe(false);
  });

  it('respects a custom gate floor', () => {
    // With floor MEDIUM, a MEDIUM uncovered finding becomes Decision needed.
    const rows = buildReport(
      [],
      [finding('CVE-2099-30', 'grype', 'MEDIUM', 'node-undici')],
      'MEDIUM',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Decision needed');
  });

  it('tolerates malformed records/findings without throwing (totality)', () => {
    expect(() =>
      buildReport(
        [
          { cve: '', status: 'not_affected' } as VexRecord,
          undefined as unknown as VexRecord,
        ],
        [
          undefined as unknown as ScannerFinding,
          { id: '', scanner: 'grype', severity: 'HIGH' } as ScannerFinding,
          { id: 'CVE-2099-40' } as ScannerFinding, // no scanner/severity
        ],
        'HIGH',
        '2026-07-14',
      ),
    ).not.toThrow();
  });

  it('tolerates ELEMENT-level junk in the arrays (null/garbage rows skipped)', () => {
    // buildReport takes arrays by contract (the shim guarantees that); its job
    // is to skip malformed ELEMENTS, not to re-check array-ness.
    const rows = buildReport(
      [
        null as unknown as VexRecord,
        { cve: '', status: 'not_affected' } as VexRecord,
        { cve: 'CVE-2099-51', status: 'not_affected', justification: 'x' },
      ],
      [
        null as unknown as ScannerFinding,
        { id: '' } as ScannerFinding,
        finding('CVE-2099-51', 'grype', 'HIGH', 'openssl'),
      ],
      'HIGH',
      '2026-07-14',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].item).toBe('CVE-2099-51');
    expect(rows[0].status).toBe('Accepted');
  });
});

describe('summarize + renderMarkdown', () => {
  it('summarize counts every status bucket', () => {
    const rows = buildReport(
      [
        {
          cve: 'CVE-2026-1',
          status: 'not_affected',
          justification: NOT_AFFECTED,
        },
      ],
      [
        finding('CVE-2026-1', 'grype', 'HIGH'),
        finding('CVE-2099-1', 'trivy', 'CRITICAL', 'openssl'), // decision needed
        finding('CVE-2099-2', 'trivy', 'LOW', 'zlib1g'), // tracked
      ],
      'HIGH',
      '2026-07-14',
    );
    const s = summarize(rows);
    expect(s['Accepted']).toBe(1);
    expect(s['Decision needed']).toBe(1);
    expect(s['Tracked']).toBe(1);
    expect(s['Revisit overdue'] + s['Stale record'] + s['Investigating']).toBe(
      0,
    );
  });

  it('renders "no action needed" when nothing needs attention', () => {
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-1',
            status: 'not_affected',
            justification: NOT_AFFECTED,
          },
        ],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('✅ **No action needed**');
    expect(md).toContain('<details>');
    expect(md).not.toContain('<details open'); // default-collapsed
    expect(md).toContain('**VEX report** —');
  });

  it('renders a Needs-attention table with signals when action is required', () => {
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-1',
            status: 'not_affected',
            justification: NOT_AFFECTED,
            revisitBy: '2026-01-01',
          },
        ],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('Needs attention (1)');
    expect(md).toContain('🔴');
    expect(md).toContain('⏰');
    expect(md).toContain('Revisit overdue');
  });

  it('shortens justification labels and flags un-CVE items in the table', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [finding('TEMP-1-ABC', 'trivy', 'CRITICAL', 'tar')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('not-in-execute-path'); // shortened enum
    expect(md).toContain('⚠️'); // un-CVE'd signal
  });

  it('passes a non-standard justification through verbatim (unknown enum)', () => {
    // A record whose justification is neither known enum is rendered as-is
    // (guards the shortJust fall-through).
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-1',
            status: 'not_affected',
            justification: 'component_not_present',
          },
        ],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('component_not_present');
  });

  it('shows adversary-unreachable short label + package column in the ledger', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [finding('CVE-2099-1', 'grype', 'MEDIUM', 'node-undici')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('adversary-unreachable');
    expect(md).toContain('node-undici'); // package column populated
  });

  it('renders investigating in the summary only when present', () => {
    const withInv = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2026-1', status: 'under_investigation' }],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(withInv).toContain('investigating');
    const without = renderMarkdown(
      buildReport(
        [],
        [finding('CVE-2099-2', 'trivy', 'LOW', 'zlib1g')],
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(without).not.toContain('investigating');
  });

  it('renders the EXACT expected markdown for a fixed input (golden — kills string/format mutants)', () => {
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-1',
            status: 'not_affected',
            justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
            revisitBy: '2026-01-01',
          },
          { cve: 'CVE-2026-2', status: 'under_investigation' },
        ],
        [
          finding('CVE-2026-1', 'grype', 'HIGH', 'libsqlite3-0'),
          finding('CVE-2026-1', 'trivy', 'MEDIUM', 'libsqlite3-0'),
          finding('CVE-2026-2', 'grype', 'HIGH', 'perl-base'),
          finding('CVE-2099-9', 'trivy', 'CRITICAL', 'openssl'), // decision needed
          finding('CVE-2099-9', 'grype', 'CRITICAL', 'libcrypto'), // 2nd pkg -> comma-join
          finding('TEMP-1-ABC', 'trivy', 'LOW', 'tar'), // un-CVE'd, tracked
        ],
        'HIGH',
        '2026-07-14',
      ),
    );
    const expected = [
      '**VEX report** — 4 item(s): 1 decision needed · 0 vex drift · 0 undocumented dismissal · 1 revisit overdue · 0 stale · 0 accepted · 1 tracked · 1 investigating',
      '',
      '**Needs attention (2):**',
      '',
      '| item | status | justification | signal |',
      '| --- | --- | --- | --- |',
      '| CVE-2099-9 | Decision needed | adversary-unreachable | 🔴 |',
      '| CVE-2026-1 | Revisit overdue | adversary-unreachable | 🔴 ⏰ |',
      '',
      '<details>',
      '<summary>Full VEX ledger (4 items) — click to expand</summary>',
      '',
      '| item | status | justification | package(s) | tools (severity) | revisit_by | signal |',
      '| --- | --- | --- | --- | --- | --- | --- |',
      '| CVE-2099-9 | Decision needed | adversary-unreachable | libcrypto, openssl | grype=CRITICAL, trivy=CRITICAL | — | 🔴 |',
      '| CVE-2026-1 | Revisit overdue | adversary-unreachable | libsqlite3-0 | grype=HIGH, trivy=MEDIUM | 2026-01-01 | 🔴 ⏰ |',
      '| CVE-2026-2 | Investigating | — | perl-base | grype=HIGH | — |  |',
      '| TEMP-1-ABC | Tracked | not-in-execute-path | tar | trivy=LOW | — | ⚠️ |',
      '',
      '</details>',
    ].join('\n');
    expect(md).toBe(expected);
  });

  it('maps EVERY never-run package to not-in-execute-path (kills the package-list mutants)', () => {
    const neverRun = [
      'bsdutils',
      'mount',
      'util-linux',
      'login.defs',
      'login',
      'apt',
      'tar',
      'gzip',
      'coreutils',
      'sysvinit-utils',
      'bash',
      'libbz2-1.0',
      'libpam-modules',
    ];
    for (const pkg of neverRun) {
      expect(suggestJustification([pkg])).toBe(
        'vulnerable_code_not_in_execute_path',
      );
    }
  });

  it('renders an em-dash for missing tools/packages/revisit in a stale row', () => {
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-9',
            status: 'not_affected',
            justification: NOT_AFFECTED,
          },
        ],
        [], // stale
        'HIGH',
        '2026-07-14',
      ),
    );
    expect(md).toContain('Stale record');
    // stale row has em-dash tools + packages
    expect(md).toMatch(/CVE-2026-9 \| Stale record \|[^|]+\| — \| — \| — \|/);
  });
});
