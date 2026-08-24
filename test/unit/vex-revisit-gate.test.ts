import {
  revisitForm,
  effectiveRevisitBy,
  recordViolation,
  gateResult,
  renderReport,
} from '../../.github/scripts/vex-revisit-gate.ts';

// Unit tests for .github/scripts/vex-revisit-gate.ts (issue #336): the gate that
// turns `.vex/README.md`'s "every record MUST carry a `revisit_by`" from a
// convention a reviewer has to catch into a hard CI failure. Two things are
// checked per record: PRESENCE (the field exists at all) and VOCABULARY (the
// value is one of the four sanctioned forms, and its argument is well-formed —
// including a REAL calendar date, not merely an ISO-shaped one).
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124), Stryker
// mutation (#122) and the fuzz tier's totality guarantee — the `.mjs` shim is
// uninstrumented, so every decision must be exercised from here (#165).

// The four sanctioned forms, from .vex/README.md § "Every record MUST carry a
// reason and a timeline". Held here as a table so a new form cannot be added to
// the implementation without a test naming it.
describe('revisitForm — the sanctioned vocabulary', () => {
  it.each([
    ['wait-for-image-rebuild', 'image-rebuild'],
    ['revisit 2026-11-24', 'date'],
    [
      'waiting-on-upstream-issue https://github.com/tlsfuzzer/python-ecdsa/security/advisories/GHSA-wj6h-64fc-37mp',
      'upstream-issue',
    ],
    ['waiting-for-fix CVE-2026-13149', 'advisory'],
    ['waiting-for-fix GHSA-3jxr-9vmj-r5cp', 'advisory'],
  ])('accepts %s', (value, form) => {
    expect(revisitForm(value)).toBe(form);
  });

  it('accepts a trailing free-text reason after the argument', () => {
    // The README asks for a trigger AND a reason, so prose after the argument is
    // encouraged; only the FORM TOKEN and its argument are machine-checked.
    expect(
      revisitForm('revisit 2026-11-24 — aws-cdk bumps its pytest pin'),
    ).toBe('date');
    expect(
      revisitForm('wait-for-image-rebuild — unfixable in the base image'),
    ).toBe('image-rebuild');
  });

  it('is whitespace-insensitive (surrounding and between words)', () => {
    expect(revisitForm('  wait-for-image-rebuild  ')).toBe('image-rebuild');
    expect(revisitForm('revisit\t2026-11-24')).toBe('date');
    expect(revisitForm('revisit  2026-11-24')).toBe('date');
  });

  it('rejects a missing or non-string value', () => {
    expect(revisitForm(undefined)).toBeNull();
    expect(revisitForm(null)).toBeNull();
    expect(revisitForm(42)).toBeNull();
    expect(revisitForm(['revisit 2026-11-24'])).toBeNull();
  });

  it('rejects an empty / whitespace-only value', () => {
    expect(revisitForm('')).toBeNull();
    expect(revisitForm('   ')).toBeNull();
  });

  it('rejects a token outside the closed vocabulary', () => {
    expect(revisitForm('soon')).toBeNull();
    expect(revisitForm('someday soon')).toBeNull();
    expect(revisitForm('wait-for-image-rebuilt')).toBeNull();
    // near-miss on the one form that takes no argument
    expect(revisitForm('wait for image rebuild')).toBeNull();
  });

  // The vocabulary is closed on the TOKEN, not just on the argument shape: an
  // invented token must be rejected even when it carries a perfectly well-formed
  // argument, so a plausible-looking trigger can't smuggle itself past the gate.
  it('rejects an unknown token even when its argument is well-formed', () => {
    expect(revisitForm('revisit-when CVE-2026-1234')).toBeNull();
    expect(revisitForm('blocked-by GHSA-3jxr-9vmj-r5cp')).toBeNull();
    expect(revisitForm('waiting-for-release 2026-11-24')).toBeNull();
    expect(
      revisitForm('see https://github.com/example/repo/issues/1'),
    ).toBeNull();
  });

  it('rejects a form whose required argument is absent', () => {
    expect(revisitForm('revisit')).toBeNull();
    expect(revisitForm('waiting-on-upstream-issue')).toBeNull();
    expect(revisitForm('waiting-for-fix')).toBeNull();
  });

  // The crux of scope item (c): `2026-02-30` is ISO-SHAPED but not a real date.
  // `new Date('2026-02-30')` does NOT return Invalid Date — V8 rolls the day
  // over into March — so a bare parse would silently accept it (and would then
  // expire the acceptance two days late).
  it('rejects a structurally-ISO but impossible calendar date', () => {
    expect(revisitForm('revisit 2026-02-30')).toBeNull();
    expect(revisitForm('revisit 2026-04-31')).toBeNull();
    expect(revisitForm('revisit 2026-02-29')).toBeNull(); // 2026 is not a leap year
    expect(revisitForm('revisit 2026-13-45')).toBeNull();
    expect(revisitForm('revisit 2026-00-10')).toBeNull();
  });

  it('accepts a real leap day', () => {
    expect(revisitForm('revisit 2024-02-29')).toBe('date');
  });

  it('rejects a date argument that is not exactly YYYY-MM-DD', () => {
    expect(revisitForm('revisit soon')).toBeNull();
    expect(revisitForm('revisit 2026-11-24T00:00:00Z')).toBeNull();
    expect(revisitForm('revisit x2026-11-24')).toBeNull();
    expect(revisitForm('revisit 2026-11-24x')).toBeNull();
  });

  it('requires an https tracker URL for the upstream-issue form', () => {
    expect(revisitForm('waiting-on-upstream-issue https://x.test/1')).toBe(
      'upstream-issue',
    );
    // http:// is rejected on purpose: a tracker link is a durable citation, so
    // it must not be a downgradeable URL.
    expect(revisitForm('waiting-on-upstream-issue http://x.test/1')).toBeNull();
    expect(revisitForm('waiting-on-upstream-issue mailto:a@x.test')).toBeNull();
    expect(revisitForm('waiting-on-upstream-issue not-a-url')).toBeNull();
  });

  it('requires a CVE or GHSA id for the waiting-for-fix form', () => {
    expect(revisitForm('waiting-for-fix cve-2026-13149')).toBe('advisory');
    // an id-shaped substring is not an id: the argument must BE the identifier
    expect(revisitForm('waiting-for-fix xCVE-2026-13149')).toBeNull();
    expect(revisitForm('waiting-for-fix pytest-9.0.3')).toBeNull();
    expect(revisitForm('waiting-for-fix upstream')).toBeNull();
  });
});

describe('effectiveRevisitBy — doc-level wins, statement-level is the fallback', () => {
  it('prefers the doc-level value over a statement-level one', () => {
    // Mirrors `doc.revisit_by ?? st.revisit_by` in vex-report.mjs — the
    // precedence every existing consumer already implements.
    expect(
      effectiveRevisitBy(
        { revisit_by: 'wait-for-image-rebuild' },
        { revisit_by: 'nonsense' },
      ),
    ).toBe('wait-for-image-rebuild');
  });
  it('falls back to the statement-level value when the doc omits it', () => {
    expect(effectiveRevisitBy({}, { revisit_by: 'revisit 2026-11-24' })).toBe(
      'revisit 2026-11-24',
    );
  });
  it('is undefined when neither level carries one', () => {
    expect(effectiveRevisitBy({}, {})).toBeUndefined();
  });
  it('tolerates a non-record statement (never throws)', () => {
    expect(effectiveRevisitBy({}, 'nope')).toBeUndefined();
    expect(effectiveRevisitBy({}, null)).toBeUndefined();
  });
});

describe('recordViolation', () => {
  const path = '.vex/CVE-2026-56846.openvex.json';
  function doc(extra: Record<string, unknown>): unknown {
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [
        { vulnerability: { name: 'CVE-2026-56846' }, status: 'not_affected' },
      ],
      ...extra,
    };
  }

  it('passes a record whose doc-level revisit_by is sanctioned', () => {
    expect(
      recordViolation({
        path,
        doc: doc({ revisit_by: 'wait-for-image-rebuild' }),
      }),
    ).toBeNull();
  });

  it('passes a record whose STATEMENT-level revisit_by is sanctioned', () => {
    expect(
      recordViolation({
        path,
        doc: {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              revisit_by: 'revisit 2026-11-24',
            },
          ],
        },
      }),
    ).toBeNull();
  });

  it('flags a record with NO revisit_by at either level', () => {
    expect(recordViolation({ path, doc: doc({}) })).toEqual({
      path,
      reason: 'missing',
      value: '',
    });
  });

  // JSON `null` means "no value", so it must read as `missing` — not as an
  // `unsanctioned <non-string object>`, which would send a reader hunting for a
  // typo that isn't there. All three shapes below are reachable, and they reach
  // the check DIFFERENTLY: `??` treats a doc-level null as absent and falls
  // through to the statement level, so only the latter two arrive as `null`.
  it.each([
    // doc-level null + a statement that omits it -> falls through to undefined
    ['doc-level null falls through', doc({ revisit_by: null })],
    // statement-level null with no doc-level value -> arrives as null
    [
      'statement-level null',
      { statements: [{ vulnerability: { name: 'CVE-1' }, revisit_by: null }] },
    ],
    // no statements at all -> the doc-level null is read directly, no `??`
    ['doc-level null with no statements', { revisit_by: null }],
  ])('flags an explicit null revisit_by as missing (%s)', (_label, doc) => {
    expect(recordViolation({ path, doc })).toEqual({
      path,
      reason: 'missing',
      value: '',
    });
  });

  it('flags an unsanctioned value and quotes it back', () => {
    expect(recordViolation({ path, doc: doc({ revisit_by: 'soon' }) })).toEqual(
      {
        path,
        reason: 'unsanctioned',
        value: 'soon',
      },
    );
  });

  it('flags a non-string value without stringifying it unsafely', () => {
    expect(recordViolation({ path, doc: doc({ revisit_by: 42 }) })).toEqual({
      path,
      reason: 'unsanctioned',
      value: '<non-string number>',
    });
  });

  it('flags an unreadable / non-object record (fail-closed)', () => {
    // the shim degrades an unparseable file to `undefined`
    expect(recordViolation({ path, doc: undefined })).toEqual({
      path,
      reason: 'unreadable',
      value: '',
    });
    expect(recordViolation({ path, doc: [] })).toEqual({
      path,
      reason: 'unreadable',
      value: '',
    });
  });

  it('requires a doc-level value when the record has no statements', () => {
    expect(recordViolation({ path, doc: { statements: [] } })).toEqual({
      path,
      reason: 'missing',
      value: '',
    });
    expect(
      recordViolation({
        path,
        doc: { statements: [], revisit_by: 'wait-for-image-rebuild' },
      }),
    ).toBeNull();
  });

  it('treats a non-array statements field as no statements', () => {
    expect(
      recordViolation({
        path,
        doc: { statements: 'nope', revisit_by: 'wait-for-image-rebuild' },
      }),
    ).toBeNull();
  });

  it('flags a multi-statement record where only ONE statement lacks a value', () => {
    expect(
      recordViolation({
        path,
        doc: {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              revisit_by: 'revisit 2026-11-24',
            },
            { vulnerability: { name: 'CVE-2' } },
          ],
        },
      }),
    ).toEqual({ path, reason: 'missing', value: '' });
  });
});

describe('gateResult', () => {
  const ok = (path: string) => ({
    path,
    doc: {
      statements: [{ vulnerability: { name: 'CVE-1' } }],
      revisit_by: 'wait-for-image-rebuild',
    },
  });
  const bad = (path: string) => ({
    path,
    doc: { statements: [{ vulnerability: { name: 'CVE-2' } }] },
  });

  it('passes when every record carries a sanctioned value', () => {
    expect(
      gateResult([ok('.vex/a.openvex.json'), ok('.vex/b.openvex.json')]),
    ).toEqual({
      outcome: 'success',
      violations: [],
      checked: 2,
    });
  });

  it('fails and lists every violating record', () => {
    const result = gateResult([
      ok('.vex/a.openvex.json'),
      bad('.vex/b.openvex.json'),
    ]);
    expect(result.outcome).toBe('failure');
    expect(result.checked).toBe(2);
    expect(result.violations).toEqual([
      { path: '.vex/b.openvex.json', reason: 'missing', value: '' },
    ]);
  });

  it('FAILS CLOSED on an empty ledger (a vacuous pass is the bug being fixed)', () => {
    expect(gateResult([])).toEqual({
      outcome: 'failure',
      violations: [],
      checked: 0,
    });
  });
});

// Exact-output assertions: the report IS the CI artifact + log surface, so its
// wording is part of the contract (and pins every string literal against
// mutation).
describe('renderReport', () => {
  it('renders the passing report', () => {
    expect(
      renderReport({ outcome: 'success', violations: [], checked: 48 }),
    ).toBe(
      [
        '.vex/ revisit_by gate (#336) — presence + vocabulary',
        'records checked: 48',
        'violations: 0',
        '',
        'PASS — every record carries a sanctioned revisit_by.',
        '',
      ].join('\n'),
    );
  });

  it('renders the failing report with one line per violation', () => {
    expect(
      renderReport({
        outcome: 'failure',
        checked: 3,
        violations: [
          { path: '.vex/a.openvex.json', reason: 'missing', value: '' },
          {
            path: '.vex/b.openvex.json',
            reason: 'unsanctioned',
            value: 'soon',
          },
          { path: '.vex/c.openvex.json', reason: 'unreadable', value: '' },
        ],
      }),
    ).toBe(
      [
        '.vex/ revisit_by gate (#336) — presence + vocabulary',
        'records checked: 3',
        'violations: 3',
        '',
        'FAIL — every .vex/ record MUST carry a revisit_by naming how the acceptance ends',
        '(see .vex/README.md § "Every record MUST carry a reason and a timeline").',
        'sanctioned forms: revisit <ISO-date> | wait-for-image-rebuild | waiting-on-upstream-issue <https url> | waiting-for-fix <CVE|GHSA>',
        '  - .vex/a.openvex.json: no revisit_by',
        '  - .vex/b.openvex.json: unsanctioned revisit_by ("soon")',
        '  - .vex/c.openvex.json: unreadable record (not a JSON object)',
        '',
      ].join('\n'),
    );
  });

  it('renders the fail-closed empty-ledger report', () => {
    expect(
      renderReport({ outcome: 'failure', violations: [], checked: 0 }),
    ).toBe(
      [
        '.vex/ revisit_by gate (#336) — presence + vocabulary',
        'records checked: 0',
        'violations: 0',
        '',
        'FAIL — no readable .vex/ record was checked; failing closed (a vacuously-green',
        'presence gate is exactly the hole this gate closes).',
        '',
      ].join('\n'),
    );
  });
});
