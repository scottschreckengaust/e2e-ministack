import {
  isCveId,
  isoDayNumber,
  isRevisitOverdue,
  isActionable,
  priorityRank,
  isRecentlyResolved,
  suggestJustification,
  buildReport,
  summarize,
  renderMarkdown,
  type ReportRow,
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

describe('priorityRank', () => {
  it('ranks every status in the intended act-now → settled order', () => {
    const order: UnifiedStatus[] = [
      'Decision needed',
      'Revisit overdue',
      'Undocumented dismissal',
      'VEX drift',
      'Stale record',
      'Resolved',
      'Investigating',
      'Accepted',
      'Tracked',
    ];
    // ranks are 0..8 in exactly this sequence (strictly increasing).
    expect(order.map(priorityRank)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8]);
  });

  it('puts every actionable status strictly above Resolved/Accepted/Tracked', () => {
    const settled = Math.min(
      priorityRank('Resolved'),
      priorityRank('Accepted'),
      priorityRank('Tracked'),
    );
    for (const s of [
      'Decision needed',
      'Revisit overdue',
      'Undocumented dismissal',
      'VEX drift',
      'Stale record',
    ] as UnifiedStatus[]) {
      expect(priorityRank(s)).toBeLessThan(settled);
    }
  });
});

describe('isRecentlyResolved', () => {
  it('is true when fixed_at day is on/after the boundary', () => {
    expect(isRecentlyResolved('2026-07-10', '2026-07-01')).toBe(true);
    expect(isRecentlyResolved('2026-07-01', '2026-07-01')).toBe(true); // on boundary
  });
  it('is false when fixed_at day is before the boundary', () => {
    expect(isRecentlyResolved('2026-06-30', '2026-07-01')).toBe(false);
  });
  it('is false for a missing/malformed fixed_at or boundary (NaN fails >=)', () => {
    expect(isRecentlyResolved(null, '2026-07-01')).toBe(false);
    expect(isRecentlyResolved('', '2026-07-01')).toBe(false);
    expect(isRecentlyResolved('not-a-date', '2026-07-01')).toBe(false);
    expect(isRecentlyResolved('2026-07-10', 'not-a-date')).toBe(false);
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
      '2026-07-14',
    );
    expect(rows).toHaveLength(1);
    // 42 and '' scanner excluded => only grype becomes a scanner link
    expect(rows[0].scanners.map((s) => s.scanner)).toEqual(['grype']);
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
      '2026-07-14',
    );
    // equal severity => localeCompare by item ascending
    expect(rows.map((r) => r.item)).toEqual(['CVE-2099-A', 'CVE-2099-B']);
  });

  it('scanners are sorted deterministically by scanner name', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-1', 'trivy', 'HIGH', 'zzz'),
        finding('CVE-2099-1', 'grype', 'HIGH', 'aaa'),
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].scanners.map((s) => s.scanner)).toEqual(['grype', 'trivy']); // sorted, not insertion order
    expect(rows[0].alertCount).toBe(2); // two alerts collapsed into one CVE
  });

  it('non-string severity becomes exactly "UNKNOWN" (kills the literal mutant)', () => {
    const rows = buildReport(
      [],
      [{ id: 'CVE-2099-X', scanner: 'g', severity: 42 as unknown as string }],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('a stale record row has maxSeverity exactly "UNKNOWN"', () => {
    const rows = buildReport(
      [{ cve: 'CVE-2099-Y', status: 'not_affected', justification: 'x' }],
      [],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('a row with no scanners renders an em-dash in the scanners column', () => {
    // stale record has no scanners -> "—" (kills the renderScanners empty mutant)
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2099-3', status: 'not_affected', justification: 'x' }],
        [],
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    // ledger columns: item · status · severity · scanners · revisit_by
    expect(md).toContain('| CVE-2099-3 | Stale record | UNKNOWN | — | — |');
  });

  it('the investigating summary suffix text is exact', () => {
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2099-I', status: 'under_investigation' }],
        [finding('CVE-2099-I', 'grype', 'HIGH', 'p')],
        'HIGH',
        '2026-07-14',
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
        '2026-07-14',
      ),
    );
    expect(md.split('\n')[0]).toBe(
      '**VEX report** — 1 CVE(s) across 1 image-scan alert(s): 0 decision needed · 0 vex drift · 0 undocumented dismissal · 0 revisit overdue · 0 stale · 0 accepted · 1 tracked',
    );
  });

  it('an accepted row renders the new 5-column ledger line (no signal column)', () => {
    const md = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2026-1', status: 'not_affected', justification: 'x' }],
        [finding('CVE-2026-1', 'grype', 'HIGH', 'p')],
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    // columns: item · status · severity · scanners · revisit_by. The scanner is
    // unlinked here (no htmlUrl on the finding) so it renders as a bare name.
    expect(md).toContain('| CVE-2026-1 | Accepted | HIGH | grype | — |');
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
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].actionNeeded).toBe(true);
    expect(rows[0].revisitOverdue).toBe(true);
    expect(rows[0].scanners).toEqual([]);
    expect(rows[0].alertCount).toBe(0);
  });

  it('a stale record with NO justification yields null (guards the ?? on the stale path)', () => {
    const rows = buildReport(
      [{ cve: 'CVE-2026-88', status: 'not_affected' }], // no justification, no finding
      [],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].suggestedJustification).toBeNull();
    // Stale is actionable, so its "why" column exercises shortJust(null) => "—".
    expect(renderMarkdown(rows)).toContain(
      '| CVE-2026-88 | Stale record | — |',
    );
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
          fixedAt: '2026-07-14', // within the recency window below
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01', // resolvedSince: the fixed alert (07-14) is inside the window
    );
    expect(rows[0].status).toBe('Resolved');
    expect(rows[0].actionNeeded).toBe(false);
    expect(rows[0].resolvedAt).toBe('2026-07-14');
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
          fixedAt: '2026-07-14', // inside the window below so the row survives
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
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
      '2026-07-14',
    );
    expect(atFloor[0].status).toBe('Decision needed');
  });

  it('renders a "resolved" suffix + a Recently-resolved block when in window', () => {
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
            fixedAt: '2026-07-13',
          },
        ],
        'HIGH',
        '2026-07-14',
        '2026-07-01', // window includes 2026-07-13
      ),
    );
    expect(md).toContain(' · 1 resolved');
    // Resolved is NOT actionable, so the clean-tree line still shows...
    expect(md).toContain('✅ **No action needed**');
    // ...and the bounded Recently-resolved block lists it (item · severity · resolved).
    expect(md).toContain('ℹ️ **Recently resolved (1):**');
    expect(md).toContain('| CVE-2099-22 | LOW | 2026-07-13 |');
  });

  it('drops a Resolved row whose fixed_at is OUTSIDE the recency window', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-23',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'fixed',
          pkg: 'zlib1g',
          fixedAt: '2026-06-01', // before the window boundary
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    // The stale resolved alert falls off entirely — no row, no noise.
    expect(rows).toHaveLength(0);
  });

  it('drops a Resolved row with NO fixed_at date (undated => outside window)', () => {
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-24',
          scanner: 'Grype',
          severity: 'LOW',
          state: 'fixed',
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    expect(rows).toHaveLength(0);
  });

  it('an overdue revisit still wins over VEX-drift (acceptance itself is due)', () => {
    const rows = buildReport(
      [{ ...na('CVE-2026-5'), revisitBy: '2026-01-01' }],
      [{ id: 'CVE-2026-5', scanner: 'Grype', severity: 'HIGH', state: 'open' }],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].status).toBe('Revisit overdue');
  });
});

describe('buildReport — merging, severity, ordering', () => {
  it('merges two scanners on one id, keeping both links and the union-max severity', () => {
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-9', 'grype', 'CRITICAL', 'perl-base'),
        finding('CVE-2099-9', 'trivy', 'medium', 'perl-base'),
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].scanners.map((s) => s.scanner)).toEqual(['grype', 'trivy']);
    expect(rows[0].alertCount).toBe(2); // two alerts collapse into one CVE
    expect(rows[0].maxSeverity).toBe('CRITICAL'); // union max
  });

  it('normalizes unknown/garbage severity to UNKNOWN', () => {
    const rows = buildReport(
      [],
      [finding('CVE-2099-10', 'grype', 'bogus')],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
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
      '2026-07-14',
    );
    expect(rows[0].maxSeverity).toBe('UNKNOWN');
  });

  it('excludes an empty-string pkg from the justification set (kills the f.pkg guard mutant)', () => {
    // Two uncovered findings on one CVE: a genuine never-run tool + one whose
    // pkg is ''. The '' must be EXCLUDED — otherwise it counts as "some other
    // package" and downgrades the suggestion from not-in-execute-path to
    // cannot-be-controlled. Dropping the `nonEmptyString(f.pkg)` guard (mutant
    // `if (true)`) adds '' to the set and flips the suggestion — observable here.
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-13', 'grype', 'HIGH', 'mount'), // never-run tool
        { id: 'CVE-2099-13', scanner: 'trivy', severity: 'HIGH', pkg: '' }, // empty pkg
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].suggestedJustification).toBe(
      'vulnerable_code_not_in_execute_path',
    );
  });

  it('preserves a scanner alert URL when the SAME scanner reports again with no URL (kills the ?? -> && mutant)', () => {
    // grype reports twice on one CVE: first with an alert URL, then without.
    // The second (URL-less) finding must NOT clobber the first real URL to ''.
    // The `?? ''` mutated to `&& ''` would wipe it — observable via the link.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-14',
          scanner: 'grype',
          severity: 'HIGH',
          htmlUrl: 'https://x.test/99',
        },
        { id: 'CVE-2099-14', scanner: 'grype', severity: 'HIGH' }, // no htmlUrl
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows[0].scanners).toEqual([
      { scanner: 'grype', htmlUrl: 'https://x.test/99' },
    ]);
  });

  it('a not_affected record with NO justification renders an em-dash', () => {
    // Covers the `vex.justification ?? null` fallback on a covered record.
    const rows = buildReport(
      [{ cve: 'CVE-2099-12', status: 'not_affected' }],
      [finding('CVE-2099-12', 'grype', 'HIGH')],
      'HIGH',
      '2026-07-14',
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
      '2026-07-14',
    );
    expect(rows.map((r) => r.item)).toEqual([
      'CVE-2099-21',
      'CVE-2099-22',
      'CVE-2099-20',
    ]);
  });

  it('orders by priority rank first — act-now leads, settled sinks', () => {
    // A Decision-needed (rank 0) CRITICAL vs an Accepted (rank 7) CRITICAL: the
    // Accepted one has HIGHER severity-tiebreak parity, so ONLY rank can put the
    // Decision-needed row first. Kills the "rank comparator dropped" mutant.
    const rows = buildReport(
      [{ cve: 'CVE-2000-1', status: 'not_affected', justification: 'x' }], // => Accepted
      [
        finding('CVE-2000-1', 'grype', 'CRITICAL', 'p'), // Accepted, rank 7
        finding('CVE-2999-9', 'grype', 'CRITICAL', 'openssl'), // uncovered => Decision needed, rank 0
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-14',
    );
    expect(rows.map((r) => [r.item, r.status])).toEqual([
      ['CVE-2999-9', 'Decision needed'],
      ['CVE-2000-1', 'Accepted'],
    ]);
  });

  it('within one rank, orders by severity desc (kills the severity-tiebreak mutant)', () => {
    // Two uncovered CRITICAL/LOW at the SAME rank? No — pick two same-rank rows:
    // both Decision needed (floor LOW so both qualify), different severity.
    const rows = buildReport(
      [],
      [
        finding('CVE-2099-A', 'grype', 'MEDIUM', 'openssl'), // Decision needed
        finding('CVE-2099-B', 'grype', 'CRITICAL', 'openssl'), // Decision needed
      ],
      'LOW',
      '2026-07-14',
      '2026-07-14',
    );
    // same rank (both Decision needed) => CRITICAL before MEDIUM
    expect(rows.map((r) => r.item)).toEqual(['CVE-2099-B', 'CVE-2099-A']);
  });

  it('within one rank + severity, orders most-recently-resolved first', () => {
    // Two Resolved rows, same LOW severity, different fixed_at => newer first.
    // The item names OPPOSE the resolvedAt order (the newer alert is 'CVE-2099-Z',
    // which sorts AFTER 'CVE-2099-A' by item), so ONLY the resolvedAt-desc
    // tiebreak can produce Z-before-A — killing both the `if (ra !== rb)` drop
    // (→ falls to item sort → A,Z) and the localeCompare-direction mutant.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-A', // sorts FIRST by item, but resolved OLDER
          scanner: 'grype',
          severity: 'LOW',
          state: 'fixed',
          fixedAt: '2026-07-02',
        },
        {
          id: 'CVE-2099-Z', // sorts LAST by item, but resolved NEWER
          scanner: 'grype',
          severity: 'LOW',
          state: 'fixed',
          fixedAt: '2026-07-12',
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    // newer (Z, 07-12) before older (A, 07-02) — resolvedAt wins over item order
    expect(rows.map((r) => r.item)).toEqual(['CVE-2099-Z', 'CVE-2099-A']);
  });

  it('a non-fixed row has resolvedAt null (kills the fixedAt-init + guard mutants)', () => {
    // An uncovered, open finding: no fixed alert => g.fixedAt stays '' => the
    // row's resolvedAt is null (not '' or a garbage literal).
    const rows = buildReport(
      [],
      [finding('CVE-2099-OPEN', 'grype', 'CRITICAL', 'openssl')],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    expect(rows[0].resolvedAt).toBeNull();
  });

  it('a stale record row has priorityRank 4 (Stale record tier)', () => {
    const rows = buildReport(
      [{ cve: 'CVE-2099-S', status: 'not_affected', justification: 'x' }],
      [], // no finding => Stale record
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    expect(rows[0].status).toBe('Stale record');
    expect(rows[0].priorityRank).toBe(4);
  });

  it('an empty fixed_at does NOT clobber a real one on the same CVE (guards the fixedAt guard)', () => {
    // Two fixed alerts for one CVE: a real fixed_at, then an empty one. The
    // empty must be IGNORED (nonEmptyString guard) — with `if (true)` the empty
    // second alert would overwrite g.fixedAt to '' and null the resolvedAt.
    const rows = buildReport(
      [],
      [
        {
          id: 'CVE-2099-F',
          scanner: 'grype',
          severity: 'LOW',
          state: 'fixed',
          fixedAt: '2026-07-13',
        },
        {
          id: 'CVE-2099-F',
          scanner: 'trivy',
          severity: 'LOW',
          state: 'fixed',
          fixedAt: '', // empty must not clobber the real date above
        },
      ],
      'HIGH',
      '2026-07-14',
      '2026-07-01',
    );
    expect(rows[0].status).toBe('Resolved');
    expect(rows[0].resolvedAt).toBe('2026-07-13');
  });

  it('flags an un-CVE-id item (isCve false)', () => {
    const rows = buildReport(
      [],
      [finding('TEMP-1-ABC', 'trivy', 'LOW', 'tar')],
      'HIGH',
      '2026-07-14',
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
      '2026-07-14',
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].item).toBe('CVE-2099-51');
    expect(rows[0].status).toBe('Accepted');
  });
});

describe('summarize + renderMarkdown', () => {
  it('renders an em-dash in the Recently-resolved block when resolvedAt is null', () => {
    // renderMarkdown is a TOTAL public fn (the fuzz tier feeds it arbitrary
    // rows). A Resolved row with null resolvedAt must render "—", not "null" —
    // covers the `resolvedAt ?? '—'` fallback in the resolved block.
    const row: ReportRow = {
      item: 'CVE-2099-Z',
      isCve: true,
      scanners: [],
      alertCount: 1,
      maxSeverity: 'LOW',
      status: 'Resolved',
      suggestedJustification: null,
      revisitBy: null,
      revisitOverdue: false,
      actionNeeded: false,
      priorityRank: priorityRank('Resolved'),
      resolvedAt: null,
    };
    const md = renderMarkdown([row]);
    expect(md).toContain('ℹ️ **Recently resolved (1):**');
    expect(md).toContain('| CVE-2099-Z | LOW | — |');
  });

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
        '2026-07-14',
      ),
    );
    expect(md).toContain('✅ **No action needed**');
    expect(md).toContain('<details>');
    expect(md).not.toContain('<details open'); // default-collapsed
    expect(md).toContain('**VEX report** —');
    // No Resolved rows => the Recently-resolved block is ENTIRELY absent, and
    // NOTHING sits between the action block and the ledger. The exact join here
    // kills both the `resolved.length > 0` mutant AND the empty-string init
    // mutant (a garbage init would appear right here).
    expect(md).toContain(
      '✅ **No action needed** — every finding is accepted, tracked, or resolved.\n\n<details>\n<summary>Full VEX ledger',
    );
    expect(md).not.toContain('Recently resolved');
  });

  it('joins multiple Recently-resolved rows with newlines (kills the join mutant)', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [
          {
            id: 'CVE-2099-71',
            scanner: 'grype',
            severity: 'LOW',
            state: 'fixed',
            fixedAt: '2026-07-12',
          },
          {
            id: 'CVE-2099-72',
            scanner: 'grype',
            severity: 'LOW',
            state: 'fixed',
            fixedAt: '2026-07-10',
          },
        ],
        'HIGH',
        '2026-07-14',
        '2026-07-01',
      ),
    );
    expect(md).toContain('ℹ️ **Recently resolved (2):**');
    // both rows present on their OWN lines (join('\n'), not concatenated)
    expect(md).toContain(
      '| CVE-2099-71 | LOW | 2026-07-12 |\n| CVE-2099-72 | LOW | 2026-07-10 |',
    );
  });

  it('renders a Needs-attention table (item · status · why) when action is required', () => {
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
        '2026-07-14',
      ),
    );
    expect(md).toContain('Needs attention (1)');
    expect(md).toContain('| item | status | why |');
    // the actionable row is the overdue acceptance, with its justification as "why"
    expect(md).toContain(
      '| CVE-2026-1 | Revisit overdue | adversary-unreachable |',
    );
  });

  it('shortens justification labels and flags un-CVE items in the table', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [finding('TEMP-1-ABC', 'trivy', 'CRITICAL', 'tar')],
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    expect(md).toContain('not-in-execute-path'); // shortened enum
    expect(md).toContain('⚠️'); // un-CVE'd signal
  });

  it('passes a non-standard justification through verbatim in the why column (unknown enum)', () => {
    // A record whose justification is neither known enum is rendered as-is
    // (guards the shortJust fall-through). shortJust now only feeds the action
    // table's "why" column, so the row must be ACTIONABLE — an overdue revisit.
    const md = renderMarkdown(
      buildReport(
        [
          {
            cve: 'CVE-2026-1',
            status: 'not_affected',
            justification: 'component_not_present',
            revisitBy: '2026-01-01', // past today => Revisit overdue (actionable)
          },
        ],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    expect(md).toContain(
      '| CVE-2026-1 | Revisit overdue | component_not_present |',
    );
  });

  it('links each scanner to its own Code-Scanning alert in the ledger', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [
          {
            id: 'CVE-2099-1',
            scanner: 'grype',
            severity: 'MEDIUM',
            pkg: 'node-undici',
            htmlUrl: 'https://example.test/alert/7',
          },
          {
            id: 'CVE-2099-1',
            scanner: 'trivy',
            severity: 'MEDIUM',
            pkg: 'node-undici',
            htmlUrl: 'https://example.test/alert/8',
          },
        ],
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    // scanners column carries a markdown link per scanner (#206 scanner-linking)
    expect(md).toContain(
      '[grype](https://example.test/alert/7), [trivy](https://example.test/alert/8)',
    );
  });

  it('renders a scanner without an alert URL as a bare (unlinked) name', () => {
    const md = renderMarkdown(
      buildReport(
        [],
        [finding('CVE-2099-1', 'grype', 'MEDIUM', 'node-undici')], // no htmlUrl
        'HIGH',
        '2026-07-14',
        '2026-07-14',
      ),
    );
    // no htmlUrl => bare name, not a markdown link (kills the link-branch mutant)
    expect(md).toContain('| CVE-2099-1 | Tracked | MEDIUM | grype | — |');
    expect(md).not.toContain('[grype](');
  });

  it('renders investigating in the summary only when present', () => {
    const withInv = renderMarkdown(
      buildReport(
        [{ cve: 'CVE-2026-1', status: 'under_investigation' }],
        [finding('CVE-2026-1', 'grype', 'HIGH')],
        'HIGH',
        '2026-07-14',
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
          {
            id: 'CVE-2026-1',
            scanner: 'grype',
            severity: 'HIGH',
            pkg: 'libsqlite3-0',
            htmlUrl: 'https://x.test/1',
          },
          {
            id: 'CVE-2026-1',
            scanner: 'trivy',
            severity: 'MEDIUM',
            pkg: 'libsqlite3-0',
            htmlUrl: 'https://x.test/2',
          },
          {
            id: 'CVE-2026-2',
            scanner: 'grype',
            severity: 'HIGH',
            pkg: 'perl-base',
            htmlUrl: 'https://x.test/3',
          },
          // decision needed, two scanners on one CVE
          {
            id: 'CVE-2099-9',
            scanner: 'trivy',
            severity: 'CRITICAL',
            pkg: 'openssl',
            htmlUrl: 'https://x.test/4',
          },
          {
            id: 'CVE-2099-9',
            scanner: 'grype',
            severity: 'CRITICAL',
            pkg: 'libcrypto',
            htmlUrl: 'https://x.test/5',
          },
          // un-CVE'd, tracked
          {
            id: 'TEMP-1-ABC',
            scanner: 'trivy',
            severity: 'LOW',
            pkg: 'tar',
            htmlUrl: 'https://x.test/6',
          },
          // recently-resolved (in the window below) => its own block + ledger row
          {
            id: 'CVE-2099-7',
            scanner: 'grype',
            severity: 'MEDIUM',
            state: 'fixed',
            pkg: 'zlib1g',
            htmlUrl: 'https://x.test/7',
            fixedAt: '2026-07-13',
          },
        ],
        'HIGH',
        '2026-07-14',
        '2026-07-01', // recently-resolved window boundary
      ),
    );
    const expected = [
      '**VEX report** — 5 CVE(s) across 7 image-scan alert(s): 1 decision needed · 0 vex drift · 0 undocumented dismissal · 1 revisit overdue · 0 stale · 0 accepted · 1 tracked · 1 investigating · 1 resolved',
      '',
      '**Needs attention (2):**',
      '',
      '| item | status | why |',
      '| --- | --- | --- |',
      '| CVE-2099-9 | Decision needed | adversary-unreachable |',
      '| CVE-2026-1 | Revisit overdue | adversary-unreachable |',
      '',
      'ℹ️ **Recently resolved (1):**',
      '',
      '| item | severity | resolved |',
      '| --- | --- | --- |',
      '| CVE-2099-7 | MEDIUM | 2026-07-13 |',
      '',
      '<details>',
      '<summary>Full VEX ledger (5 CVEs) — click to expand</summary>',
      '',
      '| item | status | severity | scanners | revisit_by |',
      '| --- | --- | --- | --- | --- |',
      '| CVE-2099-9 | Decision needed | CRITICAL | [grype](https://x.test/5), [trivy](https://x.test/4) | — |',
      '| CVE-2026-1 | Revisit overdue | HIGH | [grype](https://x.test/1), [trivy](https://x.test/2) | 2026-01-01 |',
      '| CVE-2099-7 | Resolved | MEDIUM | [grype](https://x.test/7) | — |',
      '| CVE-2026-2 | Investigating | HIGH | [grype](https://x.test/3) | — |',
      "| TEMP-1-ABC ⚠️ un-CVE'd | Tracked | LOW | [trivy](https://x.test/6) | — |",
      '',
      '</details>',
      '',
      '<details>',
      '<summary>Legend — status vocabulary, severity, revisit_by</summary>',
      '',
      '| status | meaning |',
      '| --- | --- |',
      '| Accepted | VEX `not_affected`/`fixed` + alert dismissed — gated, nothing to do |',
      '| Tracked | below the gate floor, tolerated — no action now |',
      '| Decision needed | uncovered at/above the gate floor — must VEX or fix |',
      '| VEX drift | VEX-accepted but the alert is still open — dismiss it |',
      '| Undocumented dismissal | alert dismissed with no `.vex/` record — justify or reopen |',
      '| Resolved | alert auto-fixed (finding gone) — informational |',
      '| Revisit overdue | accepted record past its `revisit_by` date |',
      '| Stale record | `.vex/` record with no current alert — prune? |',
      '| Investigating | `under_investigation` record |',
      '',
      "**severity** — GitHub's badge (NVD) severity; may differ from a scanner's gate rating.",
      '',
      '**revisit_by** — an ISO date (overdue-checkable) or an event token (e.g. `wait-for-image-rebuild`).',
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

  it('renders an em-dash for missing scanners/revisit in a stale row', () => {
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
        '2026-07-14',
      ),
    );
    expect(md).toContain('Stale record');
    // stale row: item · status · severity · scanners(—) · revisit_by(—)
    expect(md).toContain('| CVE-2026-9 | Stale record | UNKNOWN | — | — |');
  });
});
