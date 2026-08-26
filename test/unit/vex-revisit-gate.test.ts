import {
  EVIDENCE_FIELDS,
  effectiveEvidence,
  effectiveRevisitBy,
  evidenceDefect,
  gateResult,
  recordViolation,
  renderReport,
  revisitForm,
} from '../../.github/scripts/vex-revisit-gate.ts';

// Unit tests for .github/scripts/vex-revisit-gate.ts (issue #336 + #352): the
// gate that turns `.vex/README.md`'s "every record MUST carry a `revisit_by`"
// from a convention a reviewer has to catch into a hard CI failure. Three things
// are checked per record: PRESENCE (the field exists at all), VOCABULARY (the
// value is one of the five sanctioned forms, and its argument is well-formed —
// including a REAL calendar date, not merely an ISO-shaped one) and EVIDENCE (a
// `standing-acceptance`, the one form that names no future event, carries a
// complete machine-readable citation instead).
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124), Stryker
// mutation (#122) and the fuzz tier's totality guarantee — the `.mjs` shim is
// uninstrumented, so every decision must be exercised from here (#165).

// A complete, well-formed evidence block — the shape #352 sanctions, using the
// Debian security tracker (the joiner in vex-debian-tracker.ts is what produces
// such a citation). Spread-and-override in the negative cases below so each one
// differs from a PASSING record by exactly the defect under test.
const EVIDENCE = {
  source: 'debian-security-tracker',
  url: 'https://security-tracker.debian.org/tracker/CVE-2005-2541',
  source_package: 'tar',
  suite: 'trixie',
  verdict: 'unimportant',
  scope: 'local',
  checked_at: '2026-08-26',
};

// The five sanctioned forms, from .vex/README.md § "Every record MUST carry a
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
    ['standing-acceptance', 'standing'],
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
    expect(
      revisitForm('standing-acceptance — Debian rates this unimportant'),
    ).toBe('standing');
  });

  // `revisitForm` sees the STRING only, so a bare `standing-acceptance` is a
  // valid FORM here — the evidence requirement is a record-level check
  // (`recordViolation` below), because the citation lives in a sibling object.
  // Asserted explicitly so this split of responsibility cannot be read as the
  // gate letting an unevidenced standing acceptance through.
  it('classifies standing-acceptance from the string alone (evidence is checked elsewhere)', () => {
    expect(revisitForm('standing-acceptance')).toBe('standing');
    expect(
      recordViolation({
        path: '.vex/x.openvex.json',
        doc: { statements: [], revisit_by: 'standing-acceptance' },
      }),
    ).toEqual({
      path: '.vex/x.openvex.json',
      reason: 'evidence',
      value: 'no evidence object',
    });
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
    // near-misses on the two forms that take no argument
    expect(revisitForm('wait for image rebuild')).toBeNull();
    expect(revisitForm('standing-acceptances')).toBeNull();
    expect(revisitForm('standing acceptance')).toBeNull();
    expect(revisitForm('standing')).toBeNull();
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

// Resolved with the SAME precedence as `revisit_by`, so a record can declare the
// trigger and its citation together at either level and be read consistently.
describe('effectiveEvidence — doc-level wins, statement-level is the fallback', () => {
  it('prefers the doc-level evidence over a statement-level one', () => {
    expect(
      effectiveEvidence({ evidence: EVIDENCE }, { evidence: { source: 'x' } }),
    ).toBe(EVIDENCE);
  });
  it('falls back to the statement-level evidence when the doc omits it', () => {
    expect(effectiveEvidence({}, { evidence: EVIDENCE })).toBe(EVIDENCE);
  });
  it('is undefined when neither level carries one', () => {
    expect(effectiveEvidence({}, {})).toBeUndefined();
  });
  it('tolerates a non-record statement (never throws)', () => {
    expect(effectiveEvidence({}, 'nope')).toBeUndefined();
    expect(effectiveEvidence({}, null)).toBeUndefined();
  });
});

describe('evidenceDefect — what makes a standing acceptance falsifiable', () => {
  it('accepts a complete, well-formed evidence block', () => {
    expect(evidenceDefect(EVIDENCE)).toBeNull();
  });

  it('accepts extra fields alongside the required ones', () => {
    // The seven fields are a FLOOR, not a schema: a record may cite more (e.g. a
    // `nodsa_reason` quote) without the gate objecting.
    expect(
      evidenceDefect({ ...EVIDENCE, nodsa_reason: 'Minor issue' }),
    ).toBeNull();
  });

  // The MANDATORY negative: `standing-acceptance` with nothing to check is the
  // blanket-ignore the ledger forbids, so a missing/unreadable evidence object
  // must FAIL — never degrade to "nothing to validate".
  it.each([
    ['undefined', undefined],
    ['null', null],
    ['a string', 'debian says unimportant'],
    ['an array', []],
    ['a number', 7],
  ])('rejects evidence that is %s (fail-closed)', (_label, evidence) => {
    expect(evidenceDefect(evidence)).toBe('no evidence object');
  });

  it('names the FIRST absent required field, in report order', () => {
    // One defect per record keeps the report one line long; the order is
    // EVIDENCE_FIELDS', so the message is deterministic.
    expect(evidenceDefect({})).toBe('evidence.source absent');
    // Two fields dropped at once, so the assertion proves the report picks the
    // EARLIER of them (`url` precedes `suite` in EVIDENCE_FIELDS) rather than
    // whichever happened to be enumerated first. Built by filtering rather than
    // rest-destructuring: `const { url: _url, ... } = EVIDENCE` leaves bindings
    // nothing reads, which the repo's no-unused-vars rule rightly rejects.
    const withoutUrlAndSuite = Object.fromEntries(
      Object.entries(EVIDENCE).filter(
        ([field]) => field !== 'url' && field !== 'suite',
      ),
    );
    expect(evidenceDefect(withoutUrlAndSuite)).toBe('evidence.url absent');
  });

  it.each(EVIDENCE_FIELDS)('requires the %s field', (field) => {
    // Every field is individually load-bearing — dropping any one must fail, so
    // no field can be quietly demoted to optional.
    expect(evidenceDefect({ ...EVIDENCE, [field]: undefined })).toBe(
      `evidence.${field} absent`,
    );
  });

  it('rejects a non-string field and names its type', () => {
    expect(evidenceDefect({ ...EVIDENCE, suite: 13 })).toBe(
      'evidence.suite not a string (number)',
    );
    // JSON null is a value, not an omission, so it reads as a type defect
    expect(evidenceDefect({ ...EVIDENCE, verdict: null })).toBe(
      'evidence.verdict not a string (object)',
    );
  });

  it.each(['', '   ', '\t'])(
    'rejects a blank text field (%p is not a citation)',
    (blank) => {
      expect(evidenceDefect({ ...EVIDENCE, source_package: blank })).toBe(
        `evidence.source_package malformed: ${blank}`,
      );
    },
  );

  it('requires url to be a durable https citation', () => {
    // Same rule as `waiting-on-upstream-issue`: a downgradeable or non-URL
    // "citation" cannot be re-checked reliably.
    expect(evidenceDefect({ ...EVIDENCE, url: 'http://x.test/1' })).toBe(
      'evidence.url malformed: http://x.test/1',
    );
    expect(evidenceDefect({ ...EVIDENCE, url: 'security-tracker' })).toBe(
      'evidence.url malformed: security-tracker',
    );
  });

  it('requires checked_at to be a REAL calendar date', () => {
    // The same trap as the `revisit` form: `2026-02-30` is ISO-shaped and even
    // parses (V8 rolls it into March), so "when was this last confirmed" would
    // otherwise accept a date that never existed.
    expect(evidenceDefect({ ...EVIDENCE, checked_at: '2026-02-30' })).toBe(
      'evidence.checked_at malformed: 2026-02-30',
    );
    expect(evidenceDefect({ ...EVIDENCE, checked_at: 'last week' })).toBe(
      'evidence.checked_at malformed: last week',
    );
    expect(
      evidenceDefect({ ...EVIDENCE, checked_at: '2024-02-29' }),
    ).toBeNull();
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

  // #352 — the class-C form. A standing acceptance is only as good as its
  // citation, so the record-level check is where the two halves are joined.
  it('passes a standing-acceptance carrying complete doc-level evidence', () => {
    expect(
      recordViolation({
        path,
        doc: doc({ revisit_by: 'standing-acceptance', evidence: EVIDENCE }),
      }),
    ).toBeNull();
  });

  it('passes a standing-acceptance whose evidence is STATEMENT-level', () => {
    expect(
      recordViolation({
        path,
        doc: {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              revisit_by: 'standing-acceptance',
              evidence: EVIDENCE,
            },
          ],
        },
      }),
    ).toBeNull();
  });

  it('FLAGS a standing-acceptance with no evidence at all', () => {
    // The mandatory negative: without this, #352's new form would be a strictly
    // weaker acceptance than the four it joins — a token that ends nothing and
    // proves nothing.
    expect(
      recordViolation({
        path,
        doc: doc({ revisit_by: 'standing-acceptance' }),
      }),
    ).toEqual({ path, reason: 'evidence', value: 'no evidence object' });
  });

  it('FLAGS a standing-acceptance whose evidence is incomplete', () => {
    expect(
      recordViolation({
        path,
        doc: doc({
          revisit_by: 'standing-acceptance',
          evidence: { ...EVIDENCE, checked_at: undefined },
        }),
      }),
    ).toEqual({
      path,
      reason: 'evidence',
      value: 'evidence.checked_at absent',
    });
  });

  it('does NOT require evidence from the other four forms', () => {
    // Evidence is the price of naming no end EVENT; an event-triggered or dated
    // acceptance already carries its own falsifier, so demanding a citation from
    // it would be gate creep, not rigour.
    for (const revisit_by of [
      'wait-for-image-rebuild',
      'revisit 2026-11-24',
      'waiting-on-upstream-issue https://x.test/1',
      'waiting-for-fix CVE-2026-13149',
    ])
      expect(recordViolation({ path, doc: doc({ revisit_by }) })).toBeNull();
  });

  it('flags the standing statement in a mixed-form record', () => {
    // Doc-level `revisit_by` is absent, so each statement names its own form —
    // only the standing one owes evidence, and it is the one reported.
    expect(
      recordViolation({
        path,
        doc: {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              revisit_by: 'wait-for-image-rebuild',
            },
            {
              vulnerability: { name: 'CVE-2' },
              revisit_by: 'standing-acceptance',
            },
          ],
        },
      }),
    ).toEqual({ path, reason: 'evidence', value: 'no evidence object' });
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
        '.vex/ revisit_by gate (#336/#352) — presence + vocabulary + evidence',
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
        '.vex/ revisit_by gate (#336/#352) — presence + vocabulary + evidence',
        'records checked: 3',
        'violations: 3',
        '',
        'FAIL — every .vex/ record MUST carry a revisit_by naming how the acceptance ends',
        '(see .vex/README.md § "Every record MUST carry a reason and a timeline").',
        'sanctioned forms: revisit <ISO-date> | wait-for-image-rebuild | waiting-on-upstream-issue <https url> | waiting-for-fix <CVE|GHSA> | standing-acceptance (requires evidence)',
        '  - .vex/a.openvex.json: no revisit_by',
        '  - .vex/b.openvex.json: unsanctioned revisit_by ("soon")',
        '  - .vex/c.openvex.json: unreadable record (not a JSON object)',
        '',
      ].join('\n'),
    );
  });

  // The evidence contract is spelled out only when a record tripped it — the
  // common failure is a typo'd token, and an unconditional field list buries it.
  it('adds the evidence field list only when an evidence violation is present', () => {
    const report = renderReport({
      outcome: 'failure',
      checked: 2,
      violations: [
        {
          path: '.vex/a.openvex.json',
          reason: 'evidence',
          value: 'evidence.url absent',
        },
      ],
    });
    expect(report).toBe(
      [
        '.vex/ revisit_by gate (#336/#352) — presence + vocabulary + evidence',
        'records checked: 2',
        'violations: 1',
        '',
        'FAIL — every .vex/ record MUST carry a revisit_by naming how the acceptance ends',
        '(see .vex/README.md § "Every record MUST carry a reason and a timeline").',
        'sanctioned forms: revisit <ISO-date> | wait-for-image-rebuild | waiting-on-upstream-issue <https url> | waiting-for-fix <CVE|GHSA> | standing-acceptance (requires evidence)',
        'standing-acceptance evidence fields: source, url, source_package, suite, verdict, scope, checked_at',
        '  - .vex/a.openvex.json: standing-acceptance without complete evidence ("evidence.url absent")',
        '',
      ].join('\n'),
    );
  });

  it('adds the evidence field list when only SOME violations are evidence ones', () => {
    // The trigger is "at least one", not "all": a mixed batch is the realistic
    // failing report (one record mistyped its token, another forgot its evidence),
    // and an all-or-nothing condition would drop the field list from exactly the
    // report that needs it most.
    const report = renderReport({
      outcome: 'failure',
      checked: 4,
      violations: [
        { path: '.vex/a.openvex.json', reason: 'unsanctioned', value: 'soon' },
        {
          path: '.vex/b.openvex.json',
          reason: 'evidence',
          value: 'evidence.suite absent',
        },
      ],
    });
    expect(report).toContain(
      'standing-acceptance evidence fields: source, url, source_package, suite, verdict, scope, checked_at',
    );
    expect(report).toContain(
      '  - .vex/a.openvex.json: unsanctioned revisit_by',
    );
    expect(report).toContain(
      '  - .vex/b.openvex.json: standing-acceptance without complete evidence',
    );
  });

  it('omits the evidence field list when no record tripped it', () => {
    expect(
      renderReport({
        outcome: 'failure',
        checked: 1,
        violations: [
          { path: '.vex/a.openvex.json', reason: 'missing', value: '' },
        ],
      }),
    ).not.toContain('evidence fields');
  });

  it('renders the fail-closed empty-ledger report', () => {
    expect(
      renderReport({ outcome: 'failure', violations: [], checked: 0 }),
    ).toBe(
      [
        '.vex/ revisit_by gate (#336/#352) — presence + vocabulary + evidence',
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
