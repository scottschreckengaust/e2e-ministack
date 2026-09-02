// Unit tier for the delta/absolute vuln gate (issue #334).
//
// The tests that matter most here are the ANTI-SILENCER ones. A delta gate's
// failure mode is not a false red, it is a false GREEN: if the base side quietly
// yields nothing, every head finding looks "not newly introduced" and the gate
// passes indistinguishably from a legitimately-clean PR. This repo has been
// bitten by that shape three times (#347 fabricated-clean SARIF, #364 an
// artifact rooted at `/` making a corroboration arm read `no-scanner-data` 64/64
// times, and GitHub's silent auto-dismissals). So the pair
//   base-scan ERRORED  -> fail (absolute fallback)
//   base-scan EMPTY    -> pass
// is asserted explicitly: the same head findings MUST produce OPPOSITE verdicts,
// and the two states must render differently in the report.
import {
  BURNDOWN_MARKER,
  BURNDOWN_TITLE,
  SEVERITY_ORDER,
  SURFACES,
  advisorySeverities,
  burndown,
  channelFor,
  digestChange,
  findingsDocument,
  findingsFromGrype,
  findingsFromNpmAudit,
  findingsFromSarif,
  findingsFromTrivy,
  fixClass,
  floorFor,
  gate,
  laneFor,
  normEnforcement,
  normSurface,
  observedAt,
  pinnedDigest,
  renderReport,
  severityRank,
  type GateInput,
} from '../../.github/scripts/vuln-gate.ts';
import { recordAcceptances } from '../../.github/scripts/vex-ledger.ts';
import { advisoryGhsaIds } from '../../.github/scripts/npm-audit-gate.ts';

// ── fixtures ───────────────────────────────────────────────────────────────

/** A grype `matches[]` entry. */
function grypeMatch(
  id: string,
  severity: string,
  purl: string,
  fixState = 'not-fixed',
  related: string[] = [],
): unknown {
  return {
    vulnerability: { id, severity, fix: { state: fixState } },
    relatedVulnerabilities: related.map((r) => ({ id: r })),
    artifact: { name: 'pkg', purl },
  };
}

function grypeDoc(matches: unknown[]): unknown {
  return { matches };
}

function trivyDoc(vulns: unknown[]): unknown {
  return { Results: [{ Target: 'img', Vulnerabilities: vulns }] };
}

function sarifDoc(ruleIds: (string | unknown)[]): unknown {
  return { runs: [{ results: ruleIds.map((ruleId) => ({ ruleId })) }] };
}

function auditDoc(
  vulnerabilities: Record<string, { via: unknown[]; fixAvailable?: unknown }>,
): unknown {
  return { vulnerabilities };
}

// CANONICAL (upper-case) GHSA ids: every id that reaches a finding or an
// acceptance set has been through the ledger's `normId`, which upper-cases. The
// lower-case spelling is exercised deliberately in the canonicalization test
// below — asserting the lower-case form anywhere else would be asserting a
// pre-normalization value the gate never actually compares.
const GHSA_A = 'GHSA-AAAA-AAAA-AAAA';
const GHSA_B = 'GHSA-BBBB-BBBB-BBBB';

/** A minimal, always-valid gate input; each test overrides what it exercises. */
function input(over: Partial<GateInput> = {}): GateInput {
  return {
    surface: 'grype-fs',
    event: 'pull_request',
    ref: 'refs/pull/1/merge',
    defaultBranch: 'main',
    enforcement: 'blocking',
    headDoc: grypeDoc([]),
    baseDoc: grypeDoc([]),
    baseReason: '',
    baseWorkflow: undefined,
    headWorkflow: undefined,
    vexDocs: [],
    today: '2026-09-02',
    ...over,
  };
}

const HEAD_ONE = grypeDoc([
  grypeMatch('CVE-2026-1', 'High', 'pkg:npm/left-pad@1.0.0'),
]);

// ── surfaces / vocabulary ──────────────────────────────────────────────────

describe('normSurface', () => {
  it.each(SURFACES)('accepts the canonical surface %s', (surface) => {
    expect(normSurface(surface)).toBe(surface);
  });

  it('rejects an unknown surface and a non-string (fail-closed)', () => {
    expect(normSurface('grype-fs ')).toBeNull();
    expect(normSurface('made-up')).toBeNull();
    expect(normSurface(undefined)).toBeNull();
  });
});

describe('channelFor / floorFor', () => {
  it('routes the image surfaces through the digest channel at the high floor', () => {
    for (const surface of ['grype-image', 'trivy-image'] as const) {
      expect(channelFor(surface)).toBe('image-digest');
      expect(floorFor(surface)).toBe(SEVERITY_ORDER.indexOf('HIGH'));
    }
  });

  it('routes the filesystem surfaces through the registry channel at the strictest floor', () => {
    for (const surface of [
      'grype-fs',
      'trivy-fs',
      'osv',
      'npm-audit',
    ] as const) {
      expect(channelFor(surface)).toBe('registry');
      expect(floorFor(surface)).toBe(0);
    }
  });

  // An unnamed surface must NOT land on the image channel: `image-digest` is the
  // channel that grants a finding the `rebuild-blocked` excuse, and a typo may
  // not buy that excuse.
  it('defaults an unnamed surface to the registry channel', () => {
    expect(channelFor(null)).toBe('registry');
  });
});

describe('severityRank', () => {
  it.each(SEVERITY_ORDER.map((s, i) => [s, i] as const))(
    'ranks %s at %i',
    (severity, rank) => {
      expect(severityRank(severity)).toBe(rank);
      expect(severityRank(severity.toLowerCase())).toBe(rank);
    },
  );

  it('ranks an unrecognized severity as UNKNOWN but a non-string as null', () => {
    expect(severityRank('Bananas')).toBe(0);
    expect(severityRank(undefined)).toBeNull();
    expect(severityRank(4)).toBeNull();
  });
});

describe('normEnforcement', () => {
  it('treats only the exact report-only token as non-blocking', () => {
    expect(normEnforcement('report-only')).toBe('report-only');
    expect(normEnforcement('blocking')).toBe('blocking');
    expect(normEnforcement('Report-Only')).toBe('blocking');
    expect(normEnforcement(undefined)).toBe('blocking');
  });
});

// ── extractors ─────────────────────────────────────────────────────────────

describe('findingsFromGrype', () => {
  it('keys a finding on its id AND its version-stripped purl', () => {
    const [finding] = findingsFromGrype(
      grypeDoc([grypeMatch('CVE-2026-1', 'High', 'pkg:npm/left-pad@1.0.0')]),
      [],
      0,
    );
    expect(finding).toEqual({
      id: 'CVE-2026-1',
      key: 'CVE-2026-1|pkg:npm/left-pad',
      severity: 'HIGH',
      fix: 'unfixed',
    });
  });

  it('gives a namespaced purl its namespace in the key', () => {
    const [finding] = findingsFromGrype(
      grypeDoc([
        grypeMatch('CVE-2026-2', 'Low', 'pkg:deb/debian/openssl@3.0.1-2'),
      ]),
      [],
      0,
    );
    expect(finding?.key).toBe('CVE-2026-2|pkg:deb/debian/openssl');
  });

  it('keeps the SAME id on two packages as two distinct findings', () => {
    const findings = findingsFromGrype(
      grypeDoc([
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1'),
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/b@1'),
      ]),
      [],
      0,
    );
    expect(findings.map((f) => f.key)).toEqual([
      'CVE-2026-1|pkg:npm/a',
      'CVE-2026-1|pkg:npm/b',
    ]);
  });

  it('de-duplicates an identical id+purl pair', () => {
    const findings = findingsFromGrype(
      grypeDoc([
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1'),
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1'),
      ]),
      [],
      0,
    );
    expect(findings).toHaveLength(1);
  });

  // Which duplicate wins is observable, so it is pinned: FIRST-seen. The report
  // prints in this order and the burndown quotes the class, so "last one wins"
  // would silently swap a `reachable` line for an `unfixed` one (or vice versa)
  // depending on scanner ordering.
  it('keeps the FIRST of two duplicates, so the report order is stable', () => {
    const findings = findingsFromGrype(
      grypeDoc([
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1', 'fixed'),
        grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@2', 'not-fixed'),
      ]),
      [],
      0,
    );
    expect(findings).toEqual([
      {
        id: 'CVE-2026-1',
        key: 'CVE-2026-1|pkg:npm/a',
        severity: 'HIGH',
        fix: 'fixed',
      },
    ]);
  });

  it('marks a purl-less match with an explicit sentinel key', () => {
    const [finding] = findingsFromGrype(
      grypeDoc([{ vulnerability: { id: 'CVE-2026-3', severity: 'High' } }]),
      [],
      0,
    );
    expect(finding?.key).toBe('CVE-2026-3|(no-purl)');
    expect(finding?.fix).toBe('unknown');
  });

  it('reports (unknown) for a match carrying no usable id', () => {
    const [finding] = findingsFromGrype(
      grypeDoc([{ vulnerability: { severity: 'High' }, artifact: {} }]),
      [],
      0,
    );
    expect(finding?.id).toBe('(unknown)');
  });

  it('drops a match with no string severity (not an actionable finding)', () => {
    expect(
      findingsFromGrype(
        grypeDoc([{ vulnerability: { id: 'CVE-2026-4' } }]),
        [],
        0,
      ),
    ).toEqual([]);
  });

  it('applies the severity floor', () => {
    const doc = grypeDoc([
      grypeMatch('CVE-2026-5', 'Medium', 'pkg:npm/a@1'),
      grypeMatch('CVE-2026-6', 'Critical', 'pkg:npm/b@1'),
    ]);
    expect(findingsFromGrype(doc, [], 0).map((f) => f.id)).toEqual([
      'CVE-2026-5',
      'CVE-2026-6',
    ]);
    expect(
      findingsFromGrype(doc, [], SEVERITY_ORDER.indexOf('HIGH')).map(
        (f) => f.id,
      ),
    ).toEqual(['CVE-2026-6']);
  });

  it('normalizes the fix state', () => {
    const fixState = (state: string) =>
      findingsFromGrype(
        grypeDoc([grypeMatch('CVE-2026-7', 'High', 'pkg:npm/a@1', state)]),
        [],
        0,
      )[0]?.fix;
    expect(fixState('fixed')).toBe('fixed');
    expect(fixState('not-fixed')).toBe('unfixed');
    expect(fixState('wont-fix')).toBe('unfixed');
    expect(fixState('unknown')).toBe('unknown');
  });

  it('excludes a match covered by a purl-scoped .vex/ record, via its alias', () => {
    const acceptances = recordAcceptances([
      {
        statements: [
          {
            vulnerability: {
              name: 'CVE-2026-8',
              aliases: [GHSA_A],
            },
            products: [{ '@id': 'pkg:npm/left-pad@1.0.0' }],
            status: 'not_affected',
          },
        ],
      },
    ]);
    const doc = grypeDoc([
      grypeMatch('CVE-2026-8', 'High', 'pkg:npm/left-pad@1.0.0'),
      // Same record, reported the other way round (GHSA primary, CVE related).
      grypeMatch(GHSA_A, 'High', 'pkg:npm/left-pad@1.0.0', 'not-fixed', [
        'CVE-2026-8',
      ]),
      // Same CVE on a DIFFERENT product: the record does not reach it (#337).
      grypeMatch('CVE-2026-8', 'High', 'pkg:npm/other@2.0.0'),
    ]);
    expect(findingsFromGrype(doc, acceptances, 0).map((f) => f.key)).toEqual([
      'CVE-2026-8|pkg:npm/other',
    ]);
  });

  it('is total on malformed input', () => {
    expect(findingsFromGrype(undefined, [], 0)).toEqual([]);
    expect(findingsFromGrype('nope', [], 0)).toEqual([]);
    expect(findingsFromGrype({ matches: 'nope' }, [], 0)).toEqual([]);
    // A match that is not a record at all, and a record with no `vulnerability`:
    // both must be skipped, not dereferenced. This is the totality guarantee the
    // gate relies on — the extractor runs on scanner output nobody validated.
    expect(findingsFromGrype({ matches: ['nope'] }, [], 0)).toEqual([]);
    expect(findingsFromGrype({ matches: [{ artifact: {} }] }, [], 0)).toEqual(
      [],
    );
    expect(
      findingsFromGrype({ matches: [{ vulnerability: 'nope' }] }, [], 0),
    ).toEqual([]);
  });
});

describe('findingsFromTrivy', () => {
  it('keys a finding on its id and package name and reads the fix state', () => {
    const findings = findingsFromTrivy(
      trivyDoc([
        {
          VulnerabilityID: 'CVE-2026-9',
          PkgName: 'openssl',
          Severity: 'HIGH',
          FixedVersion: '3.0.2',
        },
        {
          VulnerabilityID: 'CVE-2026-10',
          PkgName: 'zlib',
          Severity: 'CRITICAL',
        },
      ]),
      0,
    );
    expect(findings).toEqual([
      {
        id: 'CVE-2026-9',
        key: 'CVE-2026-9|openssl',
        severity: 'HIGH',
        fix: 'fixed',
      },
      {
        id: 'CVE-2026-10',
        key: 'CVE-2026-10|zlib',
        severity: 'CRITICAL',
        fix: 'unfixed',
      },
    ]);
  });

  it('applies the severity floor and drops an id-less entry', () => {
    const doc = trivyDoc([
      { VulnerabilityID: 'CVE-2026-11', PkgName: 'a', Severity: 'LOW' },
      { PkgName: 'b', Severity: 'CRITICAL' },
    ]);
    expect(findingsFromTrivy(doc, SEVERITY_ORDER.indexOf('HIGH'))).toEqual([]);
    expect(findingsFromTrivy(doc, 0).map((f) => f.id)).toEqual(['CVE-2026-11']);
  });

  // A vulnerability with NO severity string is not an actionable finding — and
  // must be dropped by the same rule grype's side uses, not slip through as an
  // unranked entry (an unranked entry compares below every floor, so it would
  // reappear on the image surface where the floor is `high`).
  it('drops an entry with no severity string, at any floor', () => {
    const doc = trivyDoc([
      { VulnerabilityID: 'CVE-2026-11', PkgName: 'a' },
      { VulnerabilityID: 'CVE-2026-12', PkgName: 'b', Severity: 7 },
    ]);
    expect(findingsFromTrivy(doc, 0)).toEqual([]);
    expect(findingsFromTrivy(doc, SEVERITY_ORDER.indexOf('HIGH'))).toEqual([]);
  });

  // The EMPTY STRING cases, separately from the absent ones: trivy emits `""`
  // for "no fix known" in some feeds, and an empty `PkgName` would key a finding
  // on `CVE-x|` — a key that silently collides with every other package that
  // reports the same blank.
  it.each([
    ['absent', {}],
    ['an empty string', { PkgName: '', FixedVersion: '' }],
  ] as const)(
    'falls back to the package sentinel and an unfixed state when the fields are %s',
    (_shape, over) => {
      expect(
        findingsFromTrivy(
          trivyDoc([
            { VulnerabilityID: 'CVE-2026-12', Severity: 'HIGH', ...over },
          ]),
          0,
        ),
      ).toEqual([
        {
          id: 'CVE-2026-12',
          key: 'CVE-2026-12|(no-package)',
          severity: 'HIGH',
          fix: 'unfixed',
        },
      ]);
    },
  );

  it('is total on malformed input', () => {
    expect(findingsFromTrivy(undefined, 0)).toEqual([]);
    expect(findingsFromTrivy({ Results: 'nope' }, 0)).toEqual([]);
    expect(findingsFromTrivy({ Results: ['nope'] }, 0)).toEqual([]);
    expect(
      findingsFromTrivy({ Results: [{ Vulnerabilities: 'x' }] }, 0),
    ).toEqual([]);
    expect(findingsFromTrivy(trivyDoc(['nope']), 0)).toEqual([]);
  });
});

describe('findingsFromSarif', () => {
  it('keys a finding on its ruleId alone (the scan root differs base vs head)', () => {
    expect(findingsFromSarif(sarifDoc([GHSA_A, 'CVE-2026-13']))).toEqual([
      { id: GHSA_A, key: GHSA_A, severity: 'UNKNOWN', fix: 'unknown' },
      {
        id: 'CVE-2026-13',
        key: 'CVE-2026-13',
        severity: 'UNKNOWN',
        fix: 'unknown',
      },
    ]);
  });

  it('de-duplicates a repeated ruleId and drops a non-string one', () => {
    expect(
      findingsFromSarif(sarifDoc([GHSA_A, GHSA_A, 7, undefined])).map(
        (f) => f.id,
      ),
    ).toEqual([GHSA_A]);
  });

  // The delta key IS the id here, so a base side that spelled it in a different
  // case would look like a different finding and false-red the PR. Canonicalizing
  // through the ledger's `normId` is what keeps the two sides comparable.
  it('canonicalizes the id, so base and head keys match across letter case', () => {
    const head = findingsFromSarif(sarifDoc(['ghsa-aaaa-aaaa-aaaa']));
    expect(head.map((f) => f.id)).toEqual([GHSA_A]);
    expect(head.map((f) => f.key)).toEqual(
      findingsFromSarif(sarifDoc([GHSA_A])).map((f) => f.key),
    );
  });

  it('is total on malformed input', () => {
    expect(findingsFromSarif(undefined)).toEqual([]);
    expect(findingsFromSarif({ runs: 'nope' })).toEqual([]);
    expect(findingsFromSarif({ runs: ['nope'] })).toEqual([]);
    expect(findingsFromSarif({ runs: [{ results: 'nope' }] })).toEqual([]);
    expect(findingsFromSarif({ runs: [{ results: ['nope'] }] })).toEqual([]);
  });
});

describe('findingsFromNpmAudit', () => {
  it('emits one finding per (package, advisory) pair so a SECOND advisory on an already-flagged package is new', () => {
    expect(
      findingsFromNpmAudit(
        auditDoc({
          foo: {
            via: [{ url: `https://github.com/advisories/${GHSA_A}` }],
            fixAvailable: true,
          },
          bar: {
            via: [
              { url: `https://github.com/advisories/${GHSA_A}` },
              { url: `https://github.com/advisories/${GHSA_B}` },
            ],
          },
        }),
        new Set(),
      ),
    ).toEqual([
      { id: GHSA_A, key: `foo|${GHSA_A}`, severity: 'UNKNOWN', fix: 'fixed' },
      { id: GHSA_A, key: `bar|${GHSA_A}`, severity: 'UNKNOWN', fix: 'unfixed' },
      { id: GHSA_B, key: `bar|${GHSA_B}`, severity: 'UNKNOWN', fix: 'unfixed' },
    ]);
  });

  it('carries the advisory severity when npm reports one', () => {
    const [finding] = findingsFromNpmAudit(
      auditDoc({
        foo: { via: [{ url: `https://x/${GHSA_A}`, severity: 'high' }] },
      }),
      new Set(),
    );
    expect(finding?.severity).toBe('HIGH');
  });

  // `fixAvailable: false` is npm's explicit "no patched version reachable from
  // the registry", which is what makes the C1 predicate answerable for this
  // surface — so it must not collapse into the same value as an absent field.
  it('reads fixAvailable: false as unfixed and a fix object as fixed', () => {
    const fixStates = (fixAvailable: unknown) =>
      findingsFromNpmAudit(
        auditDoc({
          foo: { via: [{ url: `https://x/${GHSA_A}` }], fixAvailable },
        }),
        new Set(),
      ).map((f) => f.fix);
    expect(fixStates(false)).toEqual(['unfixed']);
    // npm uses the OBJECT form when it can name the bump and a bare `true` when
    // it cannot; both mean a patched version exists, so both must read as fixed.
    expect(fixStates({ name: 'foo', version: '2.0.0' })).toEqual(['fixed']);
    expect(fixStates(true)).toEqual(['fixed']);
  });

  // The invariant `findingsFromNpmAudit` leans on: the severity map's key set IS
  // the accepted-check id set, so iterating its entries can never drop a finding.
  // Asserted, not assumed — the two used to be traversed separately, and the
  // "impossible" mismatch was papered over by an unreachable `?? 'UNKNOWN'`.
  it('keeps its severity map keyed by exactly the ids the coverage check uses', () => {
    const advisory = {
      via: [
        { url: `https://x/${GHSA_A}`, severity: 'critical' },
        { url: `https://x/${GHSA_A}`, severity: 'low' },
        { url: 'https://x/not-an-advisory' },
        'some-other-package',
        7,
      ],
    };
    expect(new Set(advisorySeverities(advisory).keys())).toEqual(
      advisoryGhsaIds(advisory),
    );
    // First rating wins — a later, weaker one must not overwrite it.
    expect(advisorySeverities(advisory).get(GHSA_A)).toBe('CRITICAL');
    // Total at its own boundary, not merely at its one internal caller's.
    expect(advisorySeverities(undefined).size).toBe(0);
    expect(advisorySeverities('nope').size).toBe(0);
  });

  it('keeps an advisory with no extractable GHSA as an uncoverable finding', () => {
    const [finding] = findingsFromNpmAudit(
      auditDoc({ foo: { via: ['some-other-package'] } }),
      new Set(),
    );
    expect(finding).toEqual({
      id: '(no-advisory-id)',
      key: 'foo|(no-advisory-id)',
      severity: 'UNKNOWN',
      fix: 'unfixed',
    });
  });

  it('drops the WHOLE advisory when ANY of its ids is accepted (npm gate parity)', () => {
    expect(
      findingsFromNpmAudit(
        auditDoc({
          bar: {
            via: [
              { url: `https://x/${GHSA_A}` },
              { url: `https://x/${GHSA_B}` },
            ],
          },
        }),
        new Set([GHSA_A]),
      ),
    ).toEqual([]);
  });

  it('is total on malformed input', () => {
    expect(findingsFromNpmAudit(undefined, new Set())).toEqual([]);
    expect(findingsFromNpmAudit({ vulnerabilities: 'x' }, new Set())).toEqual(
      [],
    );
    expect(
      findingsFromNpmAudit({ vulnerabilities: { a: 1 } }, new Set()),
    ).toEqual([
      {
        id: '(no-advisory-id)',
        key: 'a|(no-advisory-id)',
        severity: 'UNKNOWN',
        fix: 'unfixed',
      },
    ]);
  });
});

// ── the C1 reachability predicate ──────────────────────────────────────────

describe('fixClass — the C1 predicate is "reachable through a channel this repo consumes"', () => {
  it('calls an upstream-fixed npm/PyPI advisory reachable (the registry IS the channel)', () => {
    expect(fixClass('registry', 'fixed', false)).toBe('reachable');
  });

  it('calls an upstream-fixed IMAGE CVE rebuild-blocked while the pin is not moving', () => {
    // `fix.state: fixed` is NOT sufficient here: Debian shipping the patch does
    // not put it in a PUBLISHED MiniStack digest, which is what the repo
    // consumes. One indirection the repo does not control.
    expect(fixClass('image-digest', 'fixed', false)).toBe('rebuild-blocked');
  });

  it('calls it reachable once the PR actually moves the digest pin', () => {
    expect(fixClass('image-digest', 'fixed', true)).toBe('reachable');
  });

  it.each([
    ['registry', 'unfixed'],
    ['registry', 'unknown'],
    ['image-digest', 'unfixed'],
    ['image-digest', 'unknown'],
  ] as const)('calls %s/%s no-upstream-fix', (channel, fix) => {
    expect(fixClass(channel, fix, true)).toBe('no-upstream-fix');
  });
});

// ── lanes ──────────────────────────────────────────────────────────────────

describe('laneFor', () => {
  it('is DELTA for a pull_request and for a push to a feature branch', () => {
    // Both events fire for a PR branch push, and BOTH report under the same
    // required context name — so a push-event run must take the delta lane too
    // or an absolute red on the feature branch would block the PR anyway.
    expect(laneFor('pull_request', 'refs/pull/9/merge', 'main')).toBe('delta');
    expect(laneFor('push', 'refs/heads/fix/issue-334', 'main')).toBe('delta');
  });

  it('is ABSOLUTE on the default branch, on schedule and on workflow_dispatch', () => {
    expect(laneFor('push', 'refs/heads/main', 'main')).toBe('absolute');
    expect(laneFor('schedule', 'refs/heads/main', 'main')).toBe('absolute');
    expect(laneFor('workflow_dispatch', 'refs/heads/x', 'main')).toBe(
      'absolute',
    );
  });

  it('falls back to ABSOLUTE when the default branch is unknown', () => {
    // Fail LOUD, not quiet: with an unknown default branch a push to the
    // default branch would otherwise diff main against itself, find every
    // finding "pre-existing" and take main permanently green.
    expect(laneFor('push', 'refs/heads/main', '')).toBe('absolute');
    expect(laneFor('push', 'refs/heads/main', undefined)).toBe('absolute');
    expect(laneFor('push', undefined, 'main')).toBe('absolute');
  });
});

// ── digest attribution (option 5) ──────────────────────────────────────────

const DIGEST_A = `sha256:${'a'.repeat(64)}`;
const DIGEST_B = `sha256:${'b'.repeat(64)}`;
const pinText = (digest: string) =>
  `      image: 'ministackorg/ministack:full@${digest}'\n`;

describe('pinnedDigest', () => {
  it('extracts the pinned MiniStack digest', () => {
    expect(pinnedDigest(pinText(DIGEST_A))).toBe(DIGEST_A);
  });

  it('accepts several occurrences of the SAME digest', () => {
    expect(pinnedDigest(pinText(DIGEST_A) + pinText(DIGEST_A))).toBe(DIGEST_A);
  });

  it('refuses to guess when the file disagrees with itself', () => {
    expect(pinnedDigest(pinText(DIGEST_A) + pinText(DIGEST_B))).toBeNull();
  });

  it('yields null for text with no pin and for a non-string', () => {
    expect(pinnedDigest('nothing here')).toBeNull();
    expect(pinnedDigest(undefined)).toBeNull();
  });
});

describe('digestChange', () => {
  it('reports unchanged / changed', () => {
    expect(digestChange(pinText(DIGEST_A), pinText(DIGEST_A))).toEqual({
      kind: 'unchanged',
      digest: DIGEST_A,
    });
    expect(digestChange(pinText(DIGEST_A), pinText(DIGEST_B))).toEqual({
      kind: 'changed',
      from: DIGEST_A,
      to: DIGEST_B,
    });
  });

  it('is UNKNOWN (fail-closed) when either side cannot be read', () => {
    expect(digestChange(undefined, pinText(DIGEST_A)).kind).toBe('unknown');
    expect(digestChange(pinText(DIGEST_A), undefined).kind).toBe('unknown');
    // Which SIDE failed is part of the diagnosis, so the reason is asserted, not
    // just the kind — the discriminated union makes the narrowing explicit.
    const both = digestChange(undefined, undefined);
    expect(both.kind === 'unknown' && both.reason).toContain('base');
    const headOnly = digestChange(pinText(DIGEST_A), undefined);
    expect(headOnly.kind === 'unknown' && headOnly.reason).toContain('head');
  });
});

// ── the verdict ────────────────────────────────────────────────────────────

describe('gate — delta lane arithmetic', () => {
  it('FAILS on a finding the PR introduces', () => {
    const result = gate(input({ headDoc: HEAD_ONE, baseDoc: grypeDoc([]) }));
    expect(result.outcome).toBe('failure');
    expect(result.effectiveLane).toBe('delta');
    expect(result.blocking.map((f) => f.id)).toEqual(['CVE-2026-1']);
    expect(result.informational).toEqual([]);
  });

  it('PASSES when every finding is already on the merge base — and still PRINTS it', () => {
    const result = gate(input({ headDoc: HEAD_ONE, baseDoc: HEAD_ONE }));
    expect(result.outcome).toBe('success');
    expect(result.blocking).toEqual([]);
    // C2 (#335): the delta lane narrows what BLOCKS, never what is printed.
    expect(result.informational.map((f) => f.id)).toEqual(['CVE-2026-1']);
    expect(renderReport(result)).toContain('CVE-2026-1');
  });

  it('splits a mixed set into the introduced and the pre-existing halves', () => {
    const result = gate(
      input({
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1'),
          grypeMatch('CVE-2026-2', 'Low', 'pkg:npm/b@1'),
        ]),
        baseDoc: grypeDoc([grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1')]),
      }),
    );
    expect(result.blocking.map((f) => f.id)).toEqual(['CVE-2026-2']);
    expect(result.informational.map((f) => f.id)).toEqual(['CVE-2026-1']);
    expect(result.outcome).toBe('failure');
  });

  it('does not mistake a version bump of an already-flagged package for a new finding', () => {
    const result = gate(
      input({
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@2.0.0'),
        ]),
        baseDoc: grypeDoc([
          grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1.0.0'),
        ]),
      }),
    );
    expect(result.outcome).toBe('success');
  });
});

describe('gate — the base side FAILS CLOSED (the anti-silencer contract)', () => {
  const headFindings = { headDoc: HEAD_ONE };

  it('an EMPTY base scan and an ERRORED base scan give OPPOSITE verdicts for the same head findings', () => {
    const empty = gate(input({ ...headFindings, baseDoc: HEAD_ONE }));
    const errored = gate(
      input({ ...headFindings, baseDoc: undefined, baseReason: '' }),
    );
    expect(empty.outcome).toBe('success');
    expect(errored.outcome).toBe('failure');
  });

  it('a base scan that legitimately found ZERO renders differently from one that produced NO DATA', () => {
    const zero = renderReport(
      gate(input({ ...headFindings, baseDoc: grypeDoc([]) })),
    );
    const noData = renderReport(
      gate(input({ ...headFindings, baseDoc: undefined })),
    );
    expect(zero).toContain('0 finding(s)');
    expect(zero).not.toContain('NO DATA');
    expect(noData).toContain('NO DATA');
    expect(noData).toContain('ABSOLUTE');
  });

  // The REASON is asserted verbatim, not just the `no-data` kind: the reason is
  // the only thing that tells a reviewer WHICH way the base side failed, and it
  // is what the report and the findings artifact carry.
  it.each([
    [
      'unparseable base output',
      { baseDoc: undefined, baseReason: '' },
      'the base scan produced no readable output',
    ],
    [
      'the workflow could not materialize the base tree',
      { baseDoc: undefined, baseReason: 'no merge base with main' },
      'no merge base with main',
    ],
    [
      'a base reason wins even when a base doc exists',
      { baseDoc: HEAD_ONE, baseReason: 'base npm audit exited non-zero' },
      'base npm audit exited non-zero',
    ],
    // A MISSING `baseReason` is not the same as an empty one: the empty string is
    // the workflow positively saying "the base side is fine", so a non-string
    // must not be read as that. A shim that failed before writing the variable
    // would otherwise hand us silence and get a delta pass.
    [
      'the base reason itself is unreadable',
      { baseDoc: HEAD_ONE, baseReason: undefined },
      'unreadable',
    ],
  ] as const)(
    'falls back to the ABSOLUTE verdict when %s',
    (_why, over, reason) => {
      const result = gate(input({ ...headFindings, ...over }));
      expect(result.lane).toBe('delta');
      expect(result.effectiveLane).toBe('absolute');
      expect(result.base).toEqual({ kind: 'no-data', reason });
      expect(result.outcome).toBe('failure');
      expect(result.notes).toEqual([
        `the base side yielded NO DATA (${reason}) — failing CLOSED to the ABSOLUTE verdict rather than reading it as "nothing new".`,
      ]);
    },
  );

  it('FAILS when the head scan itself produced nothing', () => {
    const result = gate(input({ headDoc: undefined }));
    expect(result.outcome).toBe('failure');
    expect(result.headRead).toBe(false);
    expect(result.base).toEqual({
      kind: 'no-data',
      reason: 'the head scan produced no readable output',
    });
    expect(result.notes).toEqual([
      'the head scan produced no readable output — failing CLOSED: an unread scan is not a clean one.',
      'the base side yielded NO DATA (the head scan produced no readable output) — failing CLOSED to the ABSOLUTE verdict rather than reading it as "nothing new".',
    ]);
  });

  // In the ABSOLUTE lane there is no base side to fall back FROM, so the
  // base-side note must not be printed — it would tell a reader on `main` that a
  // comparison degraded when no comparison was ever asked for.
  it('does not add the base-side fallback note in the absolute lane', () => {
    const result = gate(
      input({ event: 'schedule', headDoc: undefined, baseDoc: undefined }),
    );
    expect(result.lane).toBe('absolute');
    expect(result.outcome).toBe('failure');
    expect(result.notes).toEqual([
      'the head scan produced no readable output — failing CLOSED: an unread scan is not a clean one.',
    ]);
  });

  it('FAILS on an unknown surface rather than scoring a set it cannot name', () => {
    // A head document that WOULD yield findings under the fallback (SARIF)
    // extractor: an unnamed surface must score NOTHING, because a set it cannot
    // name is a set it cannot attribute. The failure comes from the fail-closed
    // rule, never from a guessed extractor.
    const result = gate(
      input({ surface: 'typo-fs', headDoc: sarifDoc([GHSA_A, GHSA_B]) }),
    );
    expect(result.outcome).toBe('failure');
    expect(result.surface).toBeNull();
    expect(result.channel).toBe('registry');
    expect(result.blocking).toEqual([]);
    expect(result.informational).toEqual([]);
    expect(result.base).toEqual({
      kind: 'no-data',
      reason: 'the surface name is not recognized',
    });
  });
});

describe('gate — absolute lane', () => {
  it('scores the WHOLE uncovered set regardless of the diff', () => {
    const result = gate(
      input({
        event: 'push',
        ref: 'refs/heads/main',
        headDoc: HEAD_ONE,
        baseDoc: HEAD_ONE,
      }),
    );
    expect(result.lane).toBe('absolute');
    expect(result.effectiveLane).toBe('absolute');
    expect(result.base).toEqual({
      kind: 'not-consulted',
      detail: 'absolute lane — the whole uncovered set is scored',
    });
    expect(result.blocking.map((f) => f.id)).toEqual(['CVE-2026-1']);
    expect(result.informational).toEqual([]);
    expect(result.outcome).toBe('failure');
    expect(result.notes).toEqual([]);
  });

  it('passes a genuinely clean tree', () => {
    expect(gate(input({ event: 'schedule' })).outcome).toBe('success');
  });

  // The digest probe is a DELTA-lane instrument: it answers "did THIS change move
  // the pin?", which is not a question the absolute lane asks. Probing anyway
  // would mark the whole set `reachable` on `main` whenever the last pin bump was
  // still the newest commit — turning a rebuild-blocked residual into a lie.
  it('does not probe the digest pin at all in the absolute lane', () => {
    const result = gate(
      input({
        surface: 'grype-image',
        event: 'push',
        ref: 'refs/heads/main',
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-20', 'High', 'pkg:deb/debian/a@1', 'fixed'),
        ]),
        baseWorkflow: pinText(DIGEST_A),
        headWorkflow: pinText(DIGEST_B),
      }),
    );
    expect(result.digest).toBeNull();
    expect(result.pinMovable).toBe(false);
    expect(result.base.kind).toBe('not-consulted');
    expect(findingsDocument(result).blocking.map((f) => f.class)).toEqual([
      'rebuild-blocked',
    ]);
  });
});

describe('gate — image surfaces attribute causally (option 5)', () => {
  const imageHead = grypeDoc([
    grypeMatch('CVE-2026-20', 'High', 'pkg:deb/debian/openssl@3.0.1', 'fixed'),
  ]);

  function imageInput(baseDigest: string, headDigest: string): GateInput {
    return input({
      surface: 'grype-image',
      headDoc: imageHead,
      baseDoc: undefined,
      baseWorkflow: pinText(baseDigest),
      headWorkflow: pinText(headDigest),
    });
  }

  it('PASSES but PRINTS when the PR does not touch the pinned digest', () => {
    const result = gate(imageInput(DIGEST_A, DIGEST_A));
    expect(result.outcome).toBe('success');
    expect(result.base).toEqual({
      kind: 'unattributable',
      detail: `pinned digest unchanged (${DIGEST_A})`,
    });
    expect(result.blocking).toEqual([]);
    expect(result.informational.map((f) => f.id)).toEqual(['CVE-2026-20']);
    // No note: an unmoved pin is the NORMAL case for every PR in the repo, not a
    // degradation. Announcing it would train reviewers to ignore the note lines.
    expect(result.notes).toEqual([]);
    const report = renderReport(result);
    expect(report).toContain('CVE-2026-20');
    expect(report).toContain('digest unchanged');
    // The C1 classification the maintainer asked for: fixed upstream, but the
    // repo consumes published digests, so this PR cannot reach the fix.
    expect(report).toContain('rebuild-blocked');
  });

  it('FAILS when the PR moves the digest pin (the mover owns the residual)', () => {
    const result = gate(imageInput(DIGEST_A, DIGEST_B));
    expect(result.outcome).toBe('failure');
    expect(result.pinMovable).toBe(true);
    // ATTRIBUTED, not `scanned{count:0}` and not `no-data`: the pin moved, so the
    // gate DID reach a verdict about the base side (nothing on the new digest
    // pre-dates this change) — but it reached it from the PIN, not from a second
    // scan, and the report must not claim a scan that never ran. Distinct from
    // `no-data` too: this is a positive finding about the base, not a degradation.
    expect(result.base).toEqual({
      kind: 'attributed',
      detail:
        'the pinned digest MOVED — no base image is scanned, so the whole finding set on the new digest belongs to this change',
    });
    expect(result.effectiveLane).toBe('delta');
    expect(result.notes).toEqual([
      `this change MOVES the pinned image digest (${DIGEST_A} -> ${DIGEST_B}), so every finding on the new digest is attributable to it.`,
    ]);
    expect(result.blocking.map((f) => f.id)).toEqual(['CVE-2026-20']);
    expect(renderReport(result)).toContain('reachable');
  });

  it('falls back to the ABSOLUTE verdict when the pin cannot be read on either side', () => {
    const result = gate(
      input({
        surface: 'trivy-image',
        headDoc: trivyDoc([
          { VulnerabilityID: 'CVE-2026-21', PkgName: 'zlib', Severity: 'HIGH' },
        ]),
        baseWorkflow: undefined,
        headWorkflow: pinText(DIGEST_A),
      }),
    );
    expect(result.base.kind).toBe('no-data');
    expect(result.outcome).toBe('failure');
  });

  it('applies the high+ floor, so a MEDIUM image finding is not a finding at all', () => {
    const result = gate(
      input({
        surface: 'grype-image',
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-22', 'Medium', 'pkg:deb/debian/a@1'),
        ]),
        baseWorkflow: pinText(DIGEST_A),
        headWorkflow: pinText(DIGEST_B),
      }),
    );
    expect(result.outcome).toBe('success');
    expect(result.blocking).toEqual([]);
  });
});

describe('gate — per-surface routing', () => {
  it('reads the OSV/trivy-fs surfaces from SARIF', () => {
    const result = gate(
      input({
        surface: 'osv',
        headDoc: sarifDoc([GHSA_A, GHSA_B]),
        baseDoc: sarifDoc([GHSA_A]),
      }),
    );
    expect(result.blocking.map((f) => f.id)).toEqual([GHSA_B]);
  });

  it('reads the npm-audit surface from the audit JSON, honouring an ACTIVE .vex/ record', () => {
    const vexDocs = [
      {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-30', aliases: [GHSA_A] },
            products: [{ '@id': 'pkg:npm/foo@1' }],
            status: 'affected',
          },
        ],
      },
    ];
    const headDoc = auditDoc({
      foo: { via: [{ url: `https://x/${GHSA_A}` }] },
    });
    expect(
      gate(
        input({
          surface: 'npm-audit',
          headDoc,
          baseDoc: auditDoc({}),
          vexDocs,
        }),
      ).blocking,
    ).toEqual([]);
    // ... and an EXPIRED record stops covering, so the finding comes back.
    const expired = [
      { ...vexDocs[0], revisit_by: 'revisit 2026-01-01' },
    ] as unknown[];
    expect(
      gate(
        input({
          surface: 'npm-audit',
          headDoc,
          baseDoc: auditDoc({}),
          vexDocs: expired,
        }),
      ).blocking.map((f) => f.id),
    ).toEqual([GHSA_A]);
  });

  it('keeps a report-only surface green while still printing everything', () => {
    const result = gate(
      input({
        surface: 'trivy-fs',
        enforcement: 'report-only',
        headDoc: sarifDoc([GHSA_A]),
        baseDoc: undefined,
      }),
    );
    expect(result.outcome).toBe('success');
    expect(result.enforcement).toBe('report-only');
    expect(renderReport(result)).toContain(GHSA_A);
    expect(renderReport(result)).toContain('report-only');
  });

  it('reports a clean surface as a PASS', () => {
    const report = renderReport(
      gate(
        input({
          surface: 'trivy-image',
          headDoc: trivyDoc([]),
          baseWorkflow: pinText(DIGEST_A),
          headWorkflow: pinText(DIGEST_A),
        }),
      ),
    );
    expect(report).toContain('PASS');
  });
});

// ── report + findings document ─────────────────────────────────────────────

// The report is BOTH the CI log surface and the uploaded artifact, so it is the
// only place a human ever reads the verdict from. Every shape below is asserted
// as its EXACT full text rather than by `toContain`: a substring check passes
// while a neighbouring line silently changes wording, drops a note, or renders
// "the base scan found zero findings" identically to "the base scan produced no
// data" — and that last confusion is the whole silencer class #334 exists to
// close (#335 C2: nothing gets quieter).
const HEADLINE =
  'vuln gate — %s (#334: delta on changes, absolute on the default branch)';
const INFO_HEADING =
  'informational (%n) — present but NOT attributable; printed, never hidden (#335 C2):';
const report = (...lines: string[]) => `${lines.join('\n')}\n`;

describe('renderReport', () => {
  it('renders a delta-lane FS failure: what blocks, what does not, and why', () => {
    const result = gate(
      input({
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1', 'fixed'),
          grypeMatch('CVE-2026-2', 'Low', 'pkg:npm/b@1'),
        ]),
        baseDoc: grypeDoc([grypeMatch('CVE-2026-2', 'Low', 'pkg:npm/b@1')]),
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'grype-fs'),
        'lane: delta requested / delta applied',
        'enforcement: blocking',
        'fix channel: registry',
        // The honest label: this is the count of ACTIVE accepted IDS, not of
        // files — one record can accept several aliases, and an overdue
        // `revisit_by` drops out. Calling it "records" would overstate it.
        'active .vex/ acceptance ids: 0',
        'base side: merge-base evaluated with the SAME scanner in this job — 1 finding(s)',
        'verdict: FAIL',
        '',
        'blocking (1) — attributable to this change:',
        '  - CVE-2026-1  severity=HIGH  fix=fixed  class=reachable (fix reachable through a channel this repo consumes)  key=CVE-2026-1|pkg:npm/a',
        INFO_HEADING.replace('%n', '1'),
        '  - CVE-2026-2  severity=LOW  fix=unfixed  class=no-upstream-fix (no upstream fix exists yet)  key=CVE-2026-2|pkg:npm/b',
      ),
    );
  });

  // The anti-silencer rendering: an unusable base side must SAY so, name the
  // reason, and state that the absolute verdict took over — never look like a
  // clean diff.
  it('renders the base-side NO DATA fallback loudly, as its own note', () => {
    const result = gate(
      input({
        headDoc: HEAD_ONE,
        baseDoc: undefined,
        baseReason: 'the merge base could not be determined',
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'grype-fs'),
        'lane: delta requested / absolute applied',
        'enforcement: blocking',
        'fix channel: registry',
        'active .vex/ acceptance ids: 0',
        'base side: NO DATA (the merge base could not be determined) — falling back to the ABSOLUTE verdict',
        'verdict: FAIL',
        '',
        '! the base side yielded NO DATA (the merge base could not be determined) — failing CLOSED to the ABSOLUTE verdict rather than reading it as "nothing new".',
        '',
        'blocking (1) — attributable to this change:',
        '  - CVE-2026-1  severity=HIGH  fix=unfixed  class=no-upstream-fix (no upstream fix exists yet)  key=CVE-2026-1|pkg:npm/left-pad',
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });

  it('renders an image surface with an UNCHANGED pin: nothing blocks, everything prints', () => {
    const result = gate(
      input({
        surface: 'grype-image',
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-9', 'Critical', 'pkg:deb/debian/foo@1', 'fixed'),
        ]),
        baseWorkflow: pinText(DIGEST_A),
        headWorkflow: pinText(DIGEST_A),
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'grype-image'),
        'lane: delta requested / delta applied',
        'enforcement: blocking',
        'fix channel: image-digest',
        'active .vex/ acceptance ids: 0',
        `base side: pinned digest unchanged (${DIGEST_A}) — no finding here is causally attributable to this change`,
        'verdict: PASS',
        '',
        'blocking (0) — attributable to this change:',
        INFO_HEADING.replace('%n', '1'),
        '  - CVE-2026-9  severity=CRITICAL  fix=fixed  class=rebuild-blocked (fixed upstream but NOT in any published digest this repo can pin — needs an image rebuild)  key=CVE-2026-9|pkg:deb/debian/foo',
      ),
    );
  });

  // Note the base line here: an ATTRIBUTED base side, which the previous test's
  // `NO DATA` must never be confused with — and which equally must not borrow the
  // FS lane's `0 finding(s)` wording, because no base image is scanned on this
  // path. Three base-side outcomes, three deliberately unalike strings.
  it('renders a MOVED pin: the mover owns every finding, and the fix becomes reachable', () => {
    const result = gate(
      input({
        surface: 'grype-image',
        headDoc: grypeDoc([
          grypeMatch('CVE-2026-9', 'Critical', 'pkg:deb/debian/foo@1', 'fixed'),
        ]),
        baseWorkflow: pinText(DIGEST_A),
        headWorkflow: pinText(DIGEST_B),
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'grype-image'),
        'lane: delta requested / delta applied',
        'enforcement: blocking',
        'fix channel: image-digest (this change moves the pin)',
        'active .vex/ acceptance ids: 0',
        'base side: the pinned digest MOVED — no base image is scanned, so the whole finding set on the new digest belongs to this change',
        'verdict: FAIL',
        '',
        `! this change MOVES the pinned image digest (${DIGEST_A} -> ${DIGEST_B}), so every finding on the new digest is attributable to it.`,
        '',
        'blocking (1) — attributable to this change:',
        '  - CVE-2026-9  severity=CRITICAL  fix=fixed  class=reachable (fix reachable through a channel this repo consumes)  key=CVE-2026-9|pkg:deb/debian/foo',
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });

  it('renders an unrecognized surface as an explicit unknown, with BOTH notes', () => {
    expect(renderReport(gate(input({ surface: 'typo' })))).toBe(
      report(
        HEADLINE.replace('%s', '(unknown)'),
        'lane: delta requested / absolute applied',
        'enforcement: blocking',
        'fix channel: registry',
        'active .vex/ acceptance ids: 0',
        'base side: NO DATA (the surface name is not recognized) — falling back to the ABSOLUTE verdict',
        'verdict: FAIL',
        '',
        '! unknown surface "typo" — failing CLOSED: the gate will not score a finding set it cannot name.',
        '! the base side yielded NO DATA (the surface name is not recognized) — failing CLOSED to the ABSOLUTE verdict rather than reading it as "nothing new".',
        '',
        'blocking (0) — attributable to this change:',
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });

  it('renders the absolute lane as NOT CONSULTING a base side at all', () => {
    const result = gate(
      input({
        surface: 'npm-audit',
        event: 'push',
        ref: 'refs/heads/main',
        headDoc: auditDoc({
          'left-pad': {
            via: [{ url: `https://x/${GHSA_A}`, severity: 'high' }],
            fixAvailable: true,
          },
        }),
        baseDoc: undefined,
        // An ACTIVE record for an unrelated id: the count line must report the
        // live acceptance set even when nothing here is covered by it.
        vexDocs: [{ statements: [{ vulnerability: { name: 'CVE-2026-99' } }] }],
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'npm-audit'),
        'lane: absolute requested / absolute applied',
        'enforcement: blocking',
        'fix channel: registry',
        'active .vex/ acceptance ids: 1',
        'base side: not consulted (absolute lane — the whole uncovered set is scored)',
        'verdict: FAIL',
        '',
        'blocking (1) — attributable to this change:',
        `  - ${GHSA_A}  severity=HIGH  fix=fixed  class=reachable (fix reachable through a channel this repo consumes)  key=left-pad|${GHSA_A}`,
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });

  // On the default branch there is no diff to fall back FROM, so the base-side
  // fallback note must NOT appear — only the head-unread one. Printing both
  // would invent a delta lane that never ran.
  it('renders an unread head on the absolute lane with ONE note, not two', () => {
    const result = gate(
      input({
        surface: 'osv',
        event: 'push',
        ref: 'refs/heads/main',
        headDoc: undefined,
        baseDoc: undefined,
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'osv'),
        'lane: absolute requested / absolute applied',
        'enforcement: blocking',
        'fix channel: registry',
        'active .vex/ acceptance ids: 0',
        'base side: NO DATA (the head scan produced no readable output) — falling back to the ABSOLUTE verdict',
        'verdict: FAIL',
        '',
        '! the head scan produced no readable output — failing CLOSED: an unread scan is not a clean one.',
        '',
        'blocking (0) — attributable to this change:',
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });

  // report-only still PRINTS its blocking set — the enforcement line is the only
  // thing that differs. A report-only gate that hid its findings would be the
  // C2 violation in its purest form.
  it('renders a report-only PASS whose blocking list is NOT empty', () => {
    const result = gate(
      input({
        surface: 'trivy-fs',
        enforcement: 'report-only',
        headDoc: sarifDoc([GHSA_A]),
        baseDoc: sarifDoc([]),
      }),
    );
    expect(renderReport(result)).toBe(
      report(
        HEADLINE.replace('%s', 'trivy-fs'),
        'lane: delta requested / delta applied',
        'enforcement: report-only',
        'fix channel: registry',
        'active .vex/ acceptance ids: 0',
        'base side: merge-base evaluated with the SAME scanner in this job — 0 finding(s)',
        'verdict: PASS',
        '',
        'blocking (1) — attributable to this change:',
        `  - ${GHSA_A}  severity=UNKNOWN  fix=unknown  class=no-upstream-fix (no upstream fix exists yet)  key=${GHSA_A}`,
        INFO_HEADING.replace('%n', '0'),
      ),
    );
  });
});

describe('findingsDocument', () => {
  it('carries every finding, its class and the base-side state to the burndown', () => {
    const doc = findingsDocument(
      gate(
        input({
          headDoc: grypeDoc([
            grypeMatch('CVE-2026-1', 'High', 'pkg:npm/a@1', 'fixed'),
            grypeMatch('CVE-2026-2', 'Low', 'pkg:npm/b@1'),
          ]),
          baseDoc: grypeDoc([grypeMatch('CVE-2026-2', 'Low', 'pkg:npm/b@1')]),
        }),
      ),
    );
    expect(doc.surface).toBe('grype-fs');
    expect(doc.outcome).toBe('failure');
    expect(doc.blocking).toEqual([
      {
        id: 'CVE-2026-1',
        key: 'CVE-2026-1|pkg:npm/a',
        severity: 'HIGH',
        fix: 'fixed',
        class: 'reachable',
      },
    ]);
    expect(doc.informational.map((f) => f.class)).toEqual(['no-upstream-fix']);
    expect(doc.base).toEqual({ kind: 'scanned', count: 1 });
  });

  it('names an unknown surface explicitly rather than emitting null', () => {
    expect(findingsDocument(gate(input({ surface: 'typo' }))).surface).toBe(
      '(unknown)',
    );
  });
});

// ── the absolute burndown ──────────────────────────────────────────────────

describe('burndown', () => {
  const NOW = new Date('2026-09-02T00:00:00Z');

  function doc(
    surface: string,
    blocking: unknown[],
    informational: unknown[] = [],
  ) {
    return { surface, blocking, informational };
  }

  /**
   * The expected issue body, asserted in full for the same reason the report is:
   * this text IS the burndown queue a human works from, and the fail-closed
   * clauses ("no surface reported", "N unreadable") are load-bearing prose — a
   * `toContain` check cannot tell "0 findings because the tree is clean" from
   * "0 findings because nothing was read", which is the exact confusion #334
   * exists to make impossible. The marker/heading LITERALS are spelled out here
   * rather than interpolated from the module's exports, so a mutated export
   * cannot satisfy its own assertion.
   */
  const bodyOf = (
    observed: string,
    surfaces: number,
    total: number,
    ...middle: string[]
  ) =>
    [
      '<!-- vuln-gate-absolute -->',
      '',
      `Last observed: ${observed}, by the \`vuln-gate-absolute\` job.`,
      '',
      'This is the ABSOLUTE view of every vuln surface (issue #334, option 2): the',
      'total set of findings not covered by a `.vex/` record. It does NOT gate any',
      'pull request — the per-surface required checks score only what a change ADDS.',
      'This issue is the burndown queue for the rest.',
      '',
      `Surfaces reported: ${surfaces}. Findings: ${total}.`,
      ...middle,
      '',
      '**How to clear an entry:** fix it (a bump the repo can reach), or record an',
      'honest `.vex/` acceptance with a `revisit_by` trigger. A `rebuild-blocked`',
      'entry cannot be fixed here — it needs an upstream image rebuild, so it wants a',
      '`wait-for-image-rebuild` record, not a code change.',
      '',
    ].join('\n');

  const UNREADABLE = (n: number) =>
    `**${n} surface report(s) were unreadable** and are counted as UNKNOWN, not clean.`;
  const NO_SURFACES = [
    '**FAIL-CLOSED: no surface reported a finding set.** That is not evidence of a',
    'clean tree, it is an absence of evidence — check the `vuln-gate-absolute` job',
    'for a missing or misrouted artifact.',
  ];

  it('lists every finding per surface with its class', () => {
    const result = burndown(
      [
        doc('grype-fs', [
          {
            id: 'CVE-2026-1',
            key: 'k1',
            severity: 'HIGH',
            fix: 'fixed',
            class: 'reachable',
          },
        ]),
        doc(
          'grype-image',
          [],
          [
            {
              id: 'CVE-2026-20',
              key: 'k2',
              severity: 'CRITICAL',
              fix: 'fixed',
              class: 'rebuild-blocked',
            },
          ],
        ),
      ],
      NOW,
    );
    expect(result.total).toBe(2);
    expect(result.clean).toBe(false);
    // The date is asserted as the EXACT line: a bare `toContain('2026-09-02')`
    // also passes for the full `2026-09-02T00:00:00.000Z`, so it could not tell
    // a date from a timestamp and left the day-truncation unverified.
    expect(result.body).toBe(
      bodyOf(
        '2026-09-02 (UTC)',
        2,
        2,
        '',
        '### `grype-fs` — 1 finding(s)',
        '- `CVE-2026-1` — severity HIGH, reachable',
        '',
        '### `grype-image` — 1 finding(s)',
        '- `CVE-2026-20` — severity CRITICAL, rebuild-blocked',
      ),
    );
  });

  it('reports a clean ledger', () => {
    const result = burndown([doc('grype-fs', [])], NOW);
    expect(result.clean).toBe(true);
    expect(result.total).toBe(0);
    expect(result.body).toBe(
      bodyOf(
        '2026-09-02 (UTC)',
        1,
        0,
        '',
        'No uncovered findings on any surface. 🎉',
      ),
    );
  });

  it('is total on malformed docs, and says so instead of reporting clean', () => {
    const result = burndown(['nope', undefined, { surface: 7 }], NOW);
    expect(result.total).toBe(0);
    expect(result.clean).toBe(false);
    expect(result.body).toBe(
      bodyOf('2026-09-02 (UTC)', 0, 0, '', ...NO_SURFACES, '', UNREADABLE(3)),
    );
  });

  // The mixed case is the one a substring check cannot express: one surface DID
  // report and found nothing, so the "no surface reported" clause is absent —
  // but a sibling was unreadable, so the whole thing is still NOT clean. Both
  // halves have to render independently.
  it('is NOT clean when one surface is clean and another is unreadable', () => {
    const result = burndown([doc('osv', []), 'nope'], NOW);
    expect(result.total).toBe(0);
    expect(result.clean).toBe(false);
    expect(result.body).toBe(
      bodyOf(
        '2026-09-02 (UTC)',
        1,
        0,
        '',
        UNREADABLE(1),
        '',
        '### `osv` — 0 finding(s)',
      ),
    );
  });

  // A readable surface whose findings are garbage must still be COUNTED and
  // LISTED (#335 C2 — nothing gets quieter). Dropping the entry would hide a
  // finding behind a serialization bug, which is the silencer shape again. Note
  // BOTH degenerate shapes: a non-object entry and an object whose id is the
  // empty string, since an empty id is falsy and would slip past a bare check.
  it('lists a malformed finding as unknown rather than dropping it', () => {
    const result = burndown([doc('osv', ['nope', { id: '' }])], NOW);
    expect(result.total).toBe(2);
    expect(result.clean).toBe(false);
    expect(result.body).toBe(
      bodyOf(
        '2026-09-02 (UTC)',
        1,
        2,
        '',
        '### `osv` — 2 finding(s)',
        '- `(unknown)` — severity (unknown), (unknown)',
        '- `(unknown)` — severity (unknown), (unknown)',
      ),
    );
  });

  it('fails closed on NO surface data at all rather than declaring victory', () => {
    const result = burndown([], NOW);
    expect(result.clean).toBe(false);
    expect(result.total).toBe(0);
    expect(result.body).toBe(
      bodyOf('2026-09-02 (UTC)', 0, 0, '', ...NO_SURFACES),
    );
  });

  // An unusable date must render as an explicit UNKNOWN. `1970-01-01` (what the
  // expiry-oriented `resolveNow` would hand over for an absent date) reads as a
  // real observation, and a malformed one would make `toISOString()` throw —
  // both are how a timestamp quietly lies about when the scan happened.
  it('says the date is unknown rather than printing a sentinel', () => {
    const result = burndown([doc('osv', [])], null);
    expect(result.clean).toBe(true);
    expect(result.body).not.toContain('1970');
    expect(result.body).toBe(
      bodyOf(
        'UNKNOWN — the job passed no usable date',
        1,
        0,
        '',
        'No uncovered findings on any surface. 🎉',
      ),
    );
  });

  // The marker and title are the sticky-issue identity: the marker is how the
  // job finds the issue to UPDATE instead of opening a duplicate, and the title
  // enrols it in the `review:vuln` burndown queue (#297). Both are asserted as
  // exact literals — an approximate marker silently starts a new issue thread
  // every run.
  it('exposes a stable marker and title for the sticky issue', () => {
    expect(BURNDOWN_MARKER).toBe('<!-- vuln-gate-absolute -->');
    expect(BURNDOWN_TITLE).toBe(
      'review:vuln — uncovered vulnerability findings (absolute lane)',
    );
  });

  describe('observedAt', () => {
    it('accepts a real ISO date', () => {
      expect(observedAt('2026-09-02')?.toISOString()).toBe(
        '2026-09-02T00:00:00.000Z',
      );
    });

    it('rejects an absent, empty, non-string or unparseable date', () => {
      expect(observedAt(undefined)).toBeNull();
      expect(observedAt('')).toBeNull();
      expect(observedAt(20260902)).toBeNull();
      expect(observedAt('not-a-date')).toBeNull();
    });
  });
});
