import {
  DEBIAN_TRACKER_URL,
  DEBIAN_SUITE,
  BUCKETS,
  parseDebianVersion,
  matchDebianVersion,
  indexTracker,
  entryVerdict,
  debTriples,
  classifyTriple,
  classifyTriples,
  bucketCounts,
  grypeFixStates,
  trivyFixStates,
  fixStateIndex,
  corroborate,
  renderReport,
} from '../../.github/scripts/vex-debian-tracker.ts';
import { parsePurl } from '../../.github/scripts/vex-ledger.ts';

// Unit tests for .github/scripts/vex-debian-tracker.ts (issue #352): the joiner
// that resolves Debian's OWN verdict for every `pkg:deb/debian/*` acceptance in
// the `.vex/` ledger, so a class-C ("standing") acceptance can cite evidence
// instead of asserting one.
//
// FIXTURES ARE HAND-AUTHORED, never a slice of the real ~86 MB tracker payload
// (which must never be committed): each one encodes a SHAPE the real join has to
// survive — a binNMU-rebuilt image version, an epoch the purl rendering dropped,
// a `nodsa` deferral, `urgency: unimportant`, a resolved CVE with a fix, a CVE
// present for another suite only, and an outright join miss.
//
// Imported IN-PROCESS so every decision flows through the 100% coverage gate
// (#124) and Stryker (#122); the `.mjs` shim holds only argv/fetch/read/write
// (#165), so nothing here may live there.

// A miniature security-tracker document. Real shape, invented contents.
const TRACKER = {
  // binNMU: trixie ships `2.3.2-2`; the image carries the rebuilt `…+b1`.
  acl: {
    'CVE-2026-0001': {
      scope: 'local',
      releases: {
        trixie: {
          status: 'open',
          repositories: { trixie: '2.3.2-2' },
          urgency: 'not yet assigned',
          nodsa: 'Minor issue; fixed via a point release',
          // Debian's own short justification for deferring the DSA. Distinct from
          // `nodsa` (the prose) and resolved separately, so the fixture populates
          // both — a shared spelling would hide a field read from the wrong key.
          nodsa_reason: 'postponed',
        },
      },
    },
  },
  // Epoch: trixie WRITES `1:`; trivy's purl rendering moves it into a qualifier
  // that the ledger's qualifier-less mandate then drops.
  attr: {
    'CVE-2026-0002': {
      scope: 'local',
      releases: {
        trixie: {
          status: 'open',
          repositories: { trixie: '1:2.5.2-3' },
          urgency: 'unimportant',
        },
      },
    },
  },
  // Resolved, with the fix in trixie-security and the base repo still behind.
  openssl: {
    'CVE-2026-0003': {
      scope: 'remote',
      releases: {
        trixie: {
          status: 'resolved',
          repositories: {
            trixie: '3.5.6-1~deb13u2',
            'trixie-security': '3.5.7-1~deb13u2',
          },
          fixed_version: '3.5.7-1~deb13u2',
          urgency: 'not yet assigned',
        },
      },
    },
  },
  // Open with no deferral and no fix — the residual "genuinely open" bucket.
  nodejs: {
    'CVE-2026-0004': {
      scope: 'local',
      releases: {
        trixie: {
          status: 'open',
          repositories: { trixie: '20.19.2+dfsg-1+deb13u2' },
          urgency: 'not yet assigned',
        },
      },
    },
  },
  // Present for sid only: the CVE exists in the tracker but not for our suite.
  zlib: {
    'CVE-2026-0005': {
      releases: { sid: { status: 'open', repositories: { sid: '1:1.3-1' } } },
    },
  },
};

const INDEX = indexTracker(TRACKER, DEBIAN_SUITE);

describe('constants', () => {
  it('names the tracker endpoint and the pinned image suite', () => {
    // Pinned literals: the shim fetches this URL, and the whole join is only
    // meaningful against the suite the pinned MiniStack image is built from.
    expect(DEBIAN_TRACKER_URL).toBe(
      'https://security-tracker.debian.org/tracker/data/json',
    );
    expect(DEBIAN_SUITE).toBe('trixie');
  });

  it('enumerates every bucket exactly once, in report order', () => {
    expect(BUCKETS).toEqual([
      'UNIMPORTANT-NO-FIX',
      'NO-DSA',
      'OPEN-NO-FIX',
      'FIXED-UPSTREAM',
      'AMBIGUOUS',
      'NO-VERSION-MATCH',
      'NO-CVE-IN-TRACKER',
    ]);
    expect(new Set(BUCKETS).size).toBe(BUCKETS.length);
  });
});

describe('parseDebianVersion — the two normalizations', () => {
  it('splits an epoch when one is written', () => {
    expect(parseDebianVersion('1:2.5.2-3')).toEqual({
      epoch: '1',
      base: '2.5.2-3',
      binNmu: '',
    });
  });

  it('reports a MISSING epoch as null, not as 0', () => {
    // The distinction is load-bearing: "no epoch written" is a purl-rendering
    // LOSS that may be relaxed away, whereas an explicit `0:` is a claim.
    expect(parseDebianVersion('2.5.2-3')).toEqual({
      epoch: null,
      base: '2.5.2-3',
      binNmu: '',
    });
    expect(parseDebianVersion('0:2.5.2-3')).toEqual({
      epoch: '0',
      base: '2.5.2-3',
      binNmu: '',
    });
  });

  it('strips a binNMU suffix off the base', () => {
    expect(parseDebianVersion('2.3.2-2+b1')).toEqual({
      epoch: null,
      base: '2.3.2-2',
      binNmu: '+b1',
    });
    expect(parseDebianVersion('1:2.3.2-2+b12')).toEqual({
      epoch: '1',
      base: '2.3.2-2',
      binNmu: '+b12',
    });
  });

  it('keeps a `+`-bearing upstream/revision suffix that is NOT a binNMU', () => {
    // `+dfsg`, `+deb13u2` and `~deb13u2` are part of the version proper — only
    // `+b<digits>` at the very END is a binary-only rebuild.
    expect(parseDebianVersion('20.19.2+dfsg-1+deb13u2')).toEqual({
      epoch: null,
      base: '20.19.2+dfsg-1+deb13u2',
      binNmu: '',
    });
    expect(parseDebianVersion('3.5.6-1~deb13u2')).toEqual({
      epoch: null,
      base: '3.5.6-1~deb13u2',
      binNmu: '',
    });
    // `+b` with no digits is not a binNMU marker.
    expect(parseDebianVersion('1.0-1+b')).toEqual({
      epoch: null,
      base: '1.0-1+b',
      binNmu: '',
    });
  });

  it('strips only the LAST binNMU marker', () => {
    expect(parseDebianVersion('1.0-1+b1+b2')).toEqual({
      epoch: null,
      base: '1.0-1+b1',
      binNmu: '+b2',
    });
  });

  it('treats a non-numeric epoch prefix as part of the version', () => {
    // Only `<digits>:` is an epoch per Debian policy.
    expect(parseDebianVersion('x:1.0-1')).toEqual({
      epoch: null,
      base: 'x:1.0-1',
      binNmu: '',
    });
  });

  it('reads a MULTI-digit epoch whole', () => {
    // An epoch is `<digits>:`, not `<digit>:` — Debian Policy 5.6.12 puts no
    // ceiling on it. Truncating to one digit would leave `2:1.0-1` in the base
    // and make an epoch-relaxed join impossible.
    expect(parseDebianVersion('12:1.0-1')).toEqual({
      epoch: '12',
      base: '1.0-1',
      binNmu: '',
    });
  });

  it('ignores a `<digits>:` that is not at the START of the version', () => {
    // An epoch is a PREFIX. A colon-after-digits appearing later belongs to the
    // upstream version, and reading it as an epoch would silently truncate the
    // base — fabricating a shorter version that could then join the wrong entry.
    expect(parseDebianVersion('1.0+git20250101:1-1')).toEqual({
      epoch: null,
      base: '1.0+git20250101:1-1',
      binNmu: '',
    });
  });

  it('treats a MULTI-LINE value as one opaque version, never truncating it', () => {
    // Both sides of the join are third-party JSON. A version is a single token,
    // so a value carrying a newline is not one — and the parse must keep it whole
    // rather than stopping at the first line, because a truncated base is a base
    // that can join something it has no right to.
    expect(parseDebianVersion('1:1.0-1\ntrailing junk')).toEqual({
      epoch: null,
      base: '1:1.0-1\ntrailing junk',
      binNmu: '',
    });
    expect(matchDebianVersion('1:1.0-1\ntrailing junk', '1.0-1')).toBeNull();
  });

  it('is total on the empty string', () => {
    expect(parseDebianVersion('')).toEqual({
      epoch: null,
      base: '',
      binNmu: '',
    });
  });
});

describe('matchDebianVersion — a labelled join, never a silent one', () => {
  it.each([
    ['2.3.2-2', '2.3.2-2', 'exact'],
    ['1:2.5.2-3', '1:2.5.2-3', 'exact'],
    // An explicit `0:` and an absent epoch mean the same version.
    ['0:2.5.2-3', '2.5.2-3', 'exact'],
    ['2.5.2-3', '0:2.5.2-3', 'exact'],
    // The image was rebuilt against a new library; the source version is the same.
    ['2.3.2-2+b1', '2.3.2-2', 'binnmu'],
    ['2.3.2-2', '2.3.2-2+b1', 'binnmu'],
    ['1.0-1+b1', '1.0-1+b2', 'binnmu'],
    // The purl lost the epoch the tracker writes.
    ['2.5.2-3', '1:2.5.2-3', 'epoch-stripped'],
    ['1:2.5.2-3', '2.5.2-3', 'epoch-stripped'],
    // Both relaxations at once (the real libacl1/libattr1 shape).
    ['2.5.2-3+b1', '1:2.5.2-3', 'binnmu+epoch-stripped'],
  ])('matches %s against %s as %s', (a, b, relaxation) => {
    expect(matchDebianVersion(a, b)).toBe(relaxation);
  });

  it.each([
    // Different upstream/revision — a genuine mismatch.
    ['1.0-1', '1.0-2'],
    ['2.5.2-3', '2.5.2-3.1'],
    // BOTH sides wrote an epoch and they differ: nothing was lost in rendering,
    // so this really is a different version and must NOT be relaxed.
    ['1:1.0-1', '2:1.0-1'],
    ['0:1.0-1', '1:1.0-1'],
    // A binNMU cannot bridge a different base.
    ['1.0-1+b1', '1.0-2'],
    // An EMPTY version on either side proves nothing: a purl may legally omit
    // its version, and a package may be absent from the suite repo. Joining two
    // blanks would fabricate evidence.
    ['', '1.0-1'],
    ['1.0-1', ''],
    ['', ''],
    // The empty-version guard is LOAD-BEARING, not defensive decoration: a bare
    // epoch parses to an EMPTY base (`1:` -> epoch `1`, base ``), so without the
    // explicit guard an absent version would compare base-equal to it and join as
    // `epoch-stripped` — a fabricated match out of two non-versions. Each side is
    // guarded independently, so both directions are pinned.
    ['', '1:'],
    ['1:', ''],
  ])('refuses to join %s with %s', (a, b) => {
    expect(matchDebianVersion(a, b)).toBeNull();
  });

  it('joins an epoch that arrived percent-encoded in the purl', () => {
    // The decode is already free: `parsePurl` percent-decodes components (#337),
    // so the joiner only has to handle a MISSING epoch, never an encoded one.
    const purl = parsePurl('pkg:deb/debian/libattr1@1%3A2.5.2-3');
    expect(purl?.version).toBe('1:2.5.2-3');
    expect(matchDebianVersion(purl?.version ?? '', '1:2.5.2-3')).toBe('exact');
  });
});

describe('indexTracker — one pass over the payload, keyed by CVE', () => {
  it('indexes the suite release of every source package', () => {
    expect(INDEX.get('CVE-2026-0001')).toEqual([
      {
        sourcePackage: 'acl',
        suiteVersion: '2.3.2-2',
        status: 'open',
        urgency: 'not yet assigned',
        fixedVersion: '',
        nodsa: 'Minor issue; fixed via a point release',
        // Read from `nodsa_reason`, NOT from `nodsa`: the two carry different
        // Debian fields and the report prints both.
        nodsaReason: 'postponed',
        scope: 'local',
      },
    ]);
  });

  it('reads fixed_version and the CVE-level scope', () => {
    expect(INDEX.get('CVE-2026-0003')).toEqual([
      {
        sourcePackage: 'openssl',
        suiteVersion: '3.5.6-1~deb13u2',
        status: 'resolved',
        urgency: 'not yet assigned',
        fixedVersion: '3.5.7-1~deb13u2',
        nodsa: '',
        nodsaReason: '',
        scope: 'remote',
      },
    ]);
  });

  it('omits a CVE that has no entry for the requested suite', () => {
    expect(INDEX.has('CVE-2026-0005')).toBe(false);
    expect(indexTracker(TRACKER, 'sid').has('CVE-2026-0005')).toBe(true);
  });

  it('collects EVERY source package that lists the same CVE', () => {
    const shared = indexTracker(
      {
        glibc: {
          'CVE-2026-9999': {
            releases: { trixie: { status: 'open', repositories: {} } },
          },
        },
        musl: {
          'CVE-2026-9999': {
            releases: { trixie: { status: 'open', repositories: {} } },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect(shared.get('CVE-2026-9999')?.map((e) => e.sourcePackage)).toEqual([
      'glibc',
      'musl',
    ]);
  });

  it('normalizes the CVE key so a lower-case tracker key still joins', () => {
    const lower = indexTracker(
      {
        acl: {
          'cve-2026-0001': {
            releases: { trixie: { status: 'open', repositories: {} } },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect(lower.has('CVE-2026-0001')).toBe(true);
  });

  it('yields an empty suiteVersion when the package is not in the suite repo', () => {
    const missing = indexTracker(
      {
        ghost: {
          'CVE-2026-8888': {
            releases: { trixie: { status: 'undetermined' } },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect(missing.get('CVE-2026-8888')?.[0].suiteVersion).toBe('');
  });

  it.each([
    ['a non-object payload', 'nope'],
    ['null', null],
    ['an array', [1, 2, 3]],
  ])('is total on %s', (_label, payload) => {
    expect(indexTracker(payload, DEBIAN_SUITE).size).toBe(0);
  });

  it('skips malformed package/CVE/release nodes without throwing', () => {
    const messy = indexTracker(
      {
        notAnObject: 'string',
        pkgWithBadCve: { 'CVE-2026-7777': 'string' },
        pkgWithBlankKey: { '   ': { releases: { trixie: {} } } },
        pkgWithBadReleases: { 'CVE-2026-6666': { releases: 'string' } },
        pkgWithBadSuite: {
          'CVE-2026-5555': { releases: { trixie: 'string' } },
        },
        pkgOk: {
          'CVE-2026-4444': {
            releases: { trixie: { status: 'open', repositories: {} } },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect([...messy.keys()]).toEqual(['CVE-2026-4444']);
  });

  it('coerces a non-string field to the empty string', () => {
    const odd = indexTracker(
      {
        weird: {
          'CVE-2026-3333': {
            scope: 42,
            releases: {
              trixie: {
                status: null,
                urgency: [],
                fixed_version: {},
                nodsa: 7,
                nodsa_reason: false,
                repositories: { trixie: 9 },
              },
            },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect(odd.get('CVE-2026-3333')).toEqual([
      {
        sourcePackage: 'weird',
        suiteVersion: '',
        status: '',
        urgency: '',
        fixedVersion: '',
        nodsa: '',
        nodsaReason: '',
        scope: '',
      },
    ]);
  });
});

describe('entryVerdict — Debian’s own verdict for one suite entry', () => {
  const base = {
    sourcePackage: 'p',
    suiteVersion: '1.0-1',
    status: 'open',
    urgency: 'not yet assigned',
    fixedVersion: '',
    nodsa: '',
    nodsaReason: '',
    scope: 'local',
  };

  it('reports a shipped fix as FIXED-UPSTREAM', () => {
    expect(entryVerdict({ ...base, fixedVersion: '1.0-2' })).toBe(
      'FIXED-UPSTREAM',
    );
  });

  it('reports a resolved status as FIXED-UPSTREAM even with no fixed_version', () => {
    // `resolved` is Debian's own statement that the suite is not vulnerable; the
    // two signals are independent, so either one alone is enough.
    expect(entryVerdict({ ...base, status: 'resolved' })).toBe(
      'FIXED-UPSTREAM',
    );
  });

  it('ranks a shipped fix ABOVE an unimportant urgency', () => {
    expect(
      entryVerdict({ ...base, fixedVersion: '1.0-2', urgency: 'unimportant' }),
    ).toBe('FIXED-UPSTREAM');
  });

  it('reports urgency: unimportant as UNIMPORTANT-NO-FIX', () => {
    expect(entryVerdict({ ...base, urgency: 'unimportant' })).toBe(
      'UNIMPORTANT-NO-FIX',
    );
  });

  it('ranks unimportant ABOVE a nodsa deferral', () => {
    expect(
      entryVerdict({ ...base, urgency: 'unimportant', nodsa: 'postponed' }),
    ).toBe('UNIMPORTANT-NO-FIX');
  });

  it('reports a nodsa deferral as NO-DSA', () => {
    expect(entryVerdict({ ...base, nodsa: 'Minor issue' })).toBe('NO-DSA');
  });

  it('reports a bare open entry as OPEN-NO-FIX', () => {
    expect(entryVerdict(base)).toBe('OPEN-NO-FIX');
  });
});

describe('debTriples — the pkg:deb/debian surface of the ledger', () => {
  it('yields one triple per (record, statement CVE, deb purl)', () => {
    expect(
      debTriples([
        {
          path: '.vex/CVE-2026-0001.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0001' },
                products: [
                  { '@id': 'pkg:deb/debian/libacl1@2.3.2-2+b1' },
                  { '@id': 'pkg:deb/debian/acl@2.3.2-2+b1' },
                ],
              },
            ],
          },
        },
      ]),
    ).toEqual([
      {
        path: '.vex/CVE-2026-0001.openvex.json',
        cve: 'CVE-2026-0001',
        name: 'libacl1',
        version: '2.3.2-2+b1',
        purl: 'pkg:deb/debian/libacl1@2.3.2-2+b1',
      },
      {
        path: '.vex/CVE-2026-0001.openvex.json',
        cve: 'CVE-2026-0001',
        name: 'acl',
        version: '2.3.2-2+b1',
        purl: 'pkg:deb/debian/acl@2.3.2-2+b1',
      },
    ]);
  });

  it('de-duplicates the SAME product purl carried on both `@id` and `identifiers.purl`', () => {
    // The shape EVERY committed record actually has (verified against
    // .vex/CVE-2026-54371.openvex.json): each product populates `@id` AND
    // `identifiers.purl` with the same string. `statementPurls` reads both
    // channels by design — it must not guess which field is authoritative — so it
    // yields each product purl twice, and an un-de-duplicated joiner reported 134
    // triples for a 67-triple ledger, doubling every bucket count. The
    // epoch-encoded/decoded spellings of ONE product collapse too (same decoded
    // purl), while the epoch-STRIPPED sibling is a genuinely different product
    // entry with its own join relaxation and stays its own row.
    expect(
      debTriples([
        {
          path: '.vex/dup.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0003' },
                products: [
                  {
                    '@id': 'pkg:deb/debian/libattr1@1%3A2.5.2-3',
                    identifiers: { purl: 'pkg:deb/debian/libattr1@1:2.5.2-3' },
                  },
                  {
                    '@id': 'pkg:deb/debian/libattr1@2.5.2-3',
                    identifiers: { purl: 'pkg:deb/debian/libattr1@2.5.2-3' },
                  },
                ],
              },
            ],
          },
        },
      ]),
    ).toEqual([
      {
        path: '.vex/dup.openvex.json',
        cve: 'CVE-2026-0003',
        name: 'libattr1',
        version: '1:2.5.2-3',
        purl: 'pkg:deb/debian/libattr1@1:2.5.2-3',
      },
      {
        path: '.vex/dup.openvex.json',
        cve: 'CVE-2026-0003',
        name: 'libattr1',
        version: '2.5.2-3',
        purl: 'pkg:deb/debian/libattr1@2.5.2-3',
      },
    ]);
  });

  it('keeps an identical purl that appears under two DIFFERENT records', () => {
    // The de-dup key is (path, CVE, purl), not the purl alone: two records
    // accepting the same product each deserve their own row, since the report's
    // unit of action is a RECORD.
    const products = [{ '@id': 'pkg:deb/debian/gzip@1.13-1' }];
    const rows = debTriples([
      {
        path: '.vex/a.openvex.json',
        doc: {
          statements: [{ vulnerability: { name: 'CVE-2026-0004' }, products }],
        },
      },
      {
        path: '.vex/b.openvex.json',
        doc: {
          statements: [{ vulnerability: { name: 'CVE-2026-0004' }, products }],
        },
      },
    ]);
    expect(rows.map((row) => row.path)).toEqual([
      '.vex/a.openvex.json',
      '.vex/b.openvex.json',
    ]);
  });

  it('renders the purl DECODED and qualifier-free for the report', () => {
    // Evidence fidelity: the row shows the version the join actually used, so a
    // percent-encoded epoch is visible as `1:` rather than `1%3A`.
    expect(
      debTriples([
        {
          path: '.vex/x.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0002' },
                products: [
                  {
                    identifiers: {
                      purl: 'pkg:deb/debian/libattr1@1%3A2.5.2-3?arch=arm64',
                    },
                  },
                ],
              },
            ],
          },
        },
      ]),
    ).toEqual([
      {
        path: '.vex/x.openvex.json',
        cve: 'CVE-2026-0002',
        name: 'libattr1',
        version: '1:2.5.2-3',
        purl: 'pkg:deb/debian/libattr1@1:2.5.2-3',
      },
    ]);
  });

  it('drops non-Debian purls, other purl types and unusable statements', () => {
    expect(
      debTriples([
        // Not a record at all.
        { path: '.vex/bad.openvex.json', doc: 'nope' },
        // No usable vulnerability id.
        {
          path: '.vex/anon.openvex.json',
          doc: {
            statements: [{ products: [{ '@id': 'pkg:deb/debian/a@1' }] }],
          },
        },
        // Right type, wrong distro namespace.
        {
          path: '.vex/ubuntu.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0001' },
                products: [{ '@id': 'pkg:deb/ubuntu/libacl1@2.3.2-2' }],
              },
            ],
          },
        },
        // Not a deb purl.
        {
          path: '.vex/npm.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0001' },
                products: [{ '@id': 'pkg:npm/left-pad@1.0.0' }],
              },
            ],
          },
        },
        // Right NAMESPACE, wrong type. The two components are checked
        // independently on purpose: the whole join — source-package keying, epoch
        // and binNMU relaxation, version comparison — is dpkg semantics, so a
        // non-dpkg ecosystem must not reach it even when it claims `debian`.
        // A namespace-only guard would let this through.
        {
          path: '.vex/apk.openvex.json',
          doc: {
            statements: [
              {
                vulnerability: { name: 'CVE-2026-0001' },
                products: [{ '@id': 'pkg:apk/debian/musl@1.2.5-r0' }],
              },
            ],
          },
        },
      ]),
    ).toEqual([]);
  });
});

describe('classifyTriple — bucketing one acceptance against the tracker', () => {
  const triple = (name: string, version: string, cve: string) => ({
    path: `.vex/${cve}.openvex.json`,
    cve,
    name,
    version,
    purl: `pkg:deb/debian/${name}@${version}`,
  });

  it('joins a binNMU-rebuilt image version onto the source version', () => {
    const row = classifyTriple(
      INDEX,
      triple('libacl1', '2.3.2-2+b1', 'CVE-2026-0001'),
    );
    expect(row.bucket).toBe('NO-DSA');
    expect(row.joined).toEqual([
      {
        relaxation: 'binnmu',
        entry: INDEX.get('CVE-2026-0001')?.[0],
      },
    ]);
    expect(row.candidates).toBe(1);
  });

  it('joins an epoch-stripped purl version onto the epoch-bearing suite version', () => {
    const row = classifyTriple(
      INDEX,
      triple('libattr1', '2.5.2-3', 'CVE-2026-0002'),
    );
    expect(row.bucket).toBe('UNIMPORTANT-NO-FIX');
    expect(row.joined[0].relaxation).toBe('epoch-stripped');
  });

  it('joins on the VERSION, not the package name', () => {
    // Debian keys on SOURCE packages while a purl carries a BINARY one, so a
    // name join fails by construction: `libacl1` is built from source `acl`.
    const row = classifyTriple(
      INDEX,
      triple('libacl1', '2.3.2-2', 'CVE-2026-0001'),
    );
    expect(row.joined[0].entry.sourcePackage).toBe('acl');
  });

  it('reports FIXED-UPSTREAM when the suite has a fix the image lacks', () => {
    const row = classifyTriple(
      INDEX,
      triple('libssl3t64', '3.5.6-1~deb13u2', 'CVE-2026-0003'),
    );
    expect(row.bucket).toBe('FIXED-UPSTREAM');
    expect(row.joined[0].entry.fixedVersion).toBe('3.5.7-1~deb13u2');
  });

  it('reports OPEN-NO-FIX for an open entry with no deferral', () => {
    expect(
      classifyTriple(
        INDEX,
        triple('libnode115', '20.19.2+dfsg-1+deb13u2', 'CVE-2026-0004'),
      ).bucket,
    ).toBe('OPEN-NO-FIX');
  });

  it('reports NO-CVE-IN-TRACKER when the tracker has no such CVE for the suite', () => {
    const row = classifyTriple(
      INDEX,
      triple('zlib1g', '1:1.3-1', 'CVE-2026-0005'),
    );
    expect(row.bucket).toBe('NO-CVE-IN-TRACKER');
    expect(row.candidates).toBe(0);
    expect(row.joined).toEqual([]);
  });

  it('reports NO-VERSION-MATCH when the CVE is known but no version joins', () => {
    // The worst failure mode an evidence source can have is a miss that reads
    // like "Debian has no opinion", so the miss gets its own loud bucket.
    const row = classifyTriple(
      INDEX,
      triple('libacl1', '9.9.9-1', 'CVE-2026-0001'),
    );
    expect(row.bucket).toBe('NO-VERSION-MATCH');
    expect(row.candidates).toBe(1);
    expect(row.joined).toEqual([]);
  });

  it('reports AMBIGUOUS when two joining source packages disagree', () => {
    const split = indexTracker(
      {
        a: {
          'CVE-2026-2222': {
            releases: {
              trixie: {
                status: 'open',
                repositories: { trixie: '1.0-1' },
                urgency: 'unimportant',
              },
            },
          },
        },
        b: {
          'CVE-2026-2222': {
            releases: {
              trixie: { status: 'open', repositories: { trixie: '1.0-1' } },
            },
          },
        },
      },
      DEBIAN_SUITE,
    );
    const row = classifyTriple(split, triple('libx', '1.0-1', 'CVE-2026-2222'));
    expect(row.bucket).toBe('AMBIGUOUS');
    expect(row.joined).toHaveLength(2);
  });

  it('does NOT report AMBIGUOUS when two joining packages agree', () => {
    const agree = indexTracker(
      {
        a: {
          'CVE-2026-1111': {
            releases: {
              trixie: { status: 'open', repositories: { trixie: '1.0-1' } },
            },
          },
        },
        b: {
          'CVE-2026-1111': {
            releases: {
              trixie: { status: 'open', repositories: { trixie: '1.0-1' } },
            },
          },
        },
      },
      DEBIAN_SUITE,
    );
    expect(
      classifyTriple(agree, triple('libx', '1.0-1', 'CVE-2026-1111')).bucket,
    ).toBe('OPEN-NO-FIX');
  });
});

describe('classifyTriples / bucketCounts', () => {
  const rows = classifyTriples(INDEX, [
    {
      path: '.vex/a.openvex.json',
      cve: 'CVE-2026-0002',
      name: 'libattr1',
      version: '2.5.2-3',
      purl: 'pkg:deb/debian/libattr1@2.5.2-3',
    },
    {
      path: '.vex/b.openvex.json',
      cve: 'CVE-2026-0001',
      name: 'libacl1',
      version: '2.3.2-2+b1',
      purl: 'pkg:deb/debian/libacl1@2.3.2-2+b1',
    },
  ]);

  it('classifies every triple, preserving order', () => {
    expect(rows.map((r) => r.bucket)).toEqual(['UNIMPORTANT-NO-FIX', 'NO-DSA']);
  });

  it('counts every bucket, including the empty ones', () => {
    expect(bucketCounts(rows)).toEqual([
      ['UNIMPORTANT-NO-FIX', 1],
      ['NO-DSA', 1],
      ['OPEN-NO-FIX', 0],
      ['FIXED-UPSTREAM', 0],
      ['AMBIGUOUS', 0],
      ['NO-VERSION-MATCH', 0],
      ['NO-CVE-IN-TRACKER', 0],
    ]);
  });

  it('counts nothing for an empty ledger', () => {
    expect(bucketCounts([]).every(([, n]) => n === 0)).toBe(true);
  });
});

describe('fix-state corroboration — the field no gate reads today', () => {
  it('extracts grype fix states', () => {
    expect(
      grypeFixStates({
        matches: [
          {
            vulnerability: { id: 'CVE-2026-0001', fix: { state: 'not-fixed' } },
          },
          { vulnerability: { id: 'cve-2026-0003', fix: { state: 'fixed' } } },
          // No fix node, no id, and malformed shapes contribute nothing.
          { vulnerability: { id: 'CVE-2026-0004' } },
          { vulnerability: { fix: { state: 'fixed' } } },
          'nope',
          { vulnerability: 'nope' },
        ],
      }),
    ).toEqual([
      { id: 'CVE-2026-0001', scanner: 'grype', state: 'not-fixed' },
      { id: 'CVE-2026-0003', scanner: 'grype', state: 'fixed' },
    ]);
  });

  it('extracts trivy fix states from the Status field', () => {
    expect(
      trivyFixStates({
        Results: [
          {
            Vulnerabilities: [
              { VulnerabilityID: 'CVE-2026-0001', Status: 'will_not_fix' },
              { VulnerabilityID: 'CVE-2026-0003', Status: 'fixed' },
              { VulnerabilityID: 'CVE-2026-0004' },
              { Status: 'fixed' },
              'nope',
            ],
          },
          'nope',
          { Vulnerabilities: 'nope' },
        ],
      }),
    ).toEqual([
      { id: 'CVE-2026-0001', scanner: 'trivy', state: 'will_not_fix' },
      { id: 'CVE-2026-0003', scanner: 'trivy', state: 'fixed' },
    ]);
  });

  it.each([
    ['a non-object', 'nope'],
    ['null', null],
  ])('is total on %s', (_label, doc) => {
    expect(grypeFixStates(doc)).toEqual([]);
    expect(trivyFixStates(doc)).toEqual([]);
  });

  it('groups claims by CVE id', () => {
    const index = fixStateIndex([
      { id: 'CVE-2026-0001', scanner: 'grype', state: 'not-fixed' },
      { id: 'CVE-2026-0001', scanner: 'trivy', state: 'will_not_fix' },
      { id: 'CVE-2026-0003', scanner: 'grype', state: 'fixed' },
    ]);
    expect(index.get('CVE-2026-0001')).toHaveLength(2);
    expect(index.get('CVE-2026-0003')).toHaveLength(1);
    expect(index.has('CVE-2026-0004')).toBe(false);
  });

  it('reports no-scanner-data when nothing informative is claimed', () => {
    expect(corroborate('NO-DSA', [])).toBe('no-scanner-data');
    expect(
      corroborate('NO-DSA', [{ id: 'x', scanner: 'grype', state: 'unknown' }]),
    ).toBe('no-scanner-data');
  });

  it('agrees when the scanner also sees no fix', () => {
    expect(
      corroborate('NO-DSA', [
        { id: 'x', scanner: 'grype', state: 'not-fixed' },
        { id: 'x', scanner: 'trivy', state: 'will_not_fix' },
      ]),
    ).toBe('agree');
  });

  it('agrees when the scanner also sees a fix', () => {
    expect(
      corroborate('FIXED-UPSTREAM', [
        { id: 'x', scanner: 'grype', state: 'fixed' },
      ]),
    ).toBe('agree');
  });

  it('flags a conflict when the tracker has a fix and the scanner does not', () => {
    expect(
      corroborate('FIXED-UPSTREAM', [
        { id: 'x', scanner: 'trivy', state: 'will_not_fix' },
      ]),
    ).toBe('conflict');
  });

  it('flags a conflict when the scanner has a fix and the tracker does not', () => {
    expect(
      corroborate('OPEN-NO-FIX', [
        { id: 'x', scanner: 'grype', state: 'fixed' },
      ]),
    ).toBe('conflict');
  });

  // The two scanners spell "no fix exists" six different ways — grype's
  // `fix.state` uses `not-fixed`/`wont-fix`, trivy's `Status` uses
  // `will_not_fix`/`fix_deferred`/`end_of_life`/`affected`. EVERY spelling must
  // count as informative, because a spelling that falls out of the vocabulary is
  // read as `unknown` and silently degrades the row to `no-scanner-data` — the
  // corroboration disappears with no signal that it did. One case per literal, so
  // a dropped or mistyped entry fails here rather than going quiet in the report.
  it.each([
    'not-fixed',
    'wont-fix',
    'affected',
    'will_not_fix',
    'fix_deferred',
    'end_of_life',
  ])('reads %s as an informative "no fix" claim', (state) => {
    expect(
      corroborate('OPEN-NO-FIX', [{ id: 'x', scanner: 'grype', state }]),
    ).toBe('agree');
    // …and the same claim CONFLICTS with a tracker that says a fix shipped.
    expect(
      corroborate('FIXED-UPSTREAM', [{ id: 'x', scanner: 'grype', state }]),
    ).toBe('conflict');
  });

  it('flags a conflict even when a second claim agrees', () => {
    expect(
      corroborate('OPEN-NO-FIX', [
        { id: 'x', scanner: 'grype', state: 'not-fixed' },
        { id: 'x', scanner: 'trivy', state: 'fixed' },
      ]),
    ).toBe('conflict');
  });
});

describe('renderReport', () => {
  const rows = classifyTriples(INDEX, [
    {
      path: '.vex/CVE-2026-0002.openvex.json',
      cve: 'CVE-2026-0002',
      name: 'libattr1',
      version: '2.5.2-3',
      purl: 'pkg:deb/debian/libattr1@2.5.2-3',
    },
    {
      path: '.vex/CVE-2026-0005.openvex.json',
      cve: 'CVE-2026-0005',
      name: 'zlib1g',
      version: '1:1.3-1',
      purl: 'pkg:deb/debian/zlib1g@1:1.3-1',
    },
  ]);

  it('renders the whole join as an evidence table', () => {
    const report = renderReport(DEBIAN_SUITE, rows, fixStateIndex([]));
    expect(report).toBe(
      [
        '.vex/ ↔ Debian security tracker join (#352) — REPORT ONLY',
        `source: ${DEBIAN_TRACKER_URL}`,
        'suite: trixie',
        'triples: 2 (record x CVE x deb purl)',
        '',
        'buckets',
        '  UNIMPORTANT-NO-FIX  1',
        '  NO-DSA              0',
        '  OPEN-NO-FIX         0',
        '  FIXED-UPSTREAM      0',
        '  AMBIGUOUS           0',
        '  NO-VERSION-MATCH    0',
        '  NO-CVE-IN-TRACKER   1',
        '',
        'rows',
        '  .vex/CVE-2026-0002.openvex.json | CVE-2026-0002 | pkg:deb/debian/libattr1@2.5.2-3 | UNIMPORTANT-NO-FIX | src=attr suite-version=1:2.5.2-3 match=epoch-stripped status=open urgency=unimportant fixed= nodsa= nodsa-reason= scope=local | fix-state=no-scanner-data',
        '  .vex/CVE-2026-0005.openvex.json | CVE-2026-0005 | pkg:deb/debian/zlib1g@1:1.3-1 | NO-CVE-IN-TRACKER | candidates=0 | fix-state=no-scanner-data',
        '',
        'NOTE — reported, not applied: this job edits no .vex/ record (#322). It is',
        'REPORT-ONLY and never a required gate: it fetches an ~86 MB third-party',
        'file, so gating on it would make CI depend on an external service (#335 C1).',
        '',
      ].join('\n'),
    );
  });

  it('renders every joined candidate of an ambiguous row', () => {
    const split = indexTracker(
      {
        a: {
          'CVE-2026-2222': {
            releases: {
              trixie: {
                status: 'open',
                repositories: { trixie: '1.0-1' },
                urgency: 'unimportant',
              },
            },
          },
        },
        b: {
          'CVE-2026-2222': {
            releases: {
              trixie: { status: 'open', repositories: { trixie: '1.0-1' } },
            },
          },
        },
      },
      DEBIAN_SUITE,
    );
    const report = renderReport(
      DEBIAN_SUITE,
      classifyTriples(split, [
        {
          path: '.vex/x.openvex.json',
          cve: 'CVE-2026-2222',
          name: 'libx',
          version: '1.0-1',
          purl: 'pkg:deb/debian/libx@1.0-1',
        },
      ]),
      fixStateIndex([]),
    );
    expect(report).toContain('src=a ');
    expect(report).toContain('src=b ');
    expect(report).toContain('| AMBIGUOUS |');
    // The candidates are SEPARATED, not run together: an AMBIGUOUS row is exactly
    // the row a human has to read field-by-field, and two concatenated evidence
    // strings (`…scope=src=b …`) would be unparseable by eye and by grep.
    expect(report).toContain('scope= ; src=b ');
  });

  it('renders the NO-VERSION-MATCH candidate count as evidence', () => {
    const report = renderReport(
      DEBIAN_SUITE,
      classifyTriples(INDEX, [
        {
          path: '.vex/m.openvex.json',
          cve: 'CVE-2026-0001',
          name: 'libacl1',
          version: '9.9.9-1',
          purl: 'pkg:deb/debian/libacl1@9.9.9-1',
        },
      ]),
      fixStateIndex([]),
    );
    expect(report).toContain('| NO-VERSION-MATCH | candidates=1 |');
  });

  it('surfaces a fix-state conflict on the row', () => {
    const report = renderReport(
      DEBIAN_SUITE,
      classifyTriples(INDEX, [
        {
          path: '.vex/CVE-2026-0004.openvex.json',
          cve: 'CVE-2026-0004',
          name: 'libnode115',
          version: '20.19.2+dfsg-1+deb13u2',
          purl: 'pkg:deb/debian/libnode115@20.19.2+dfsg-1+deb13u2',
        },
      ]),
      fixStateIndex([
        { id: 'CVE-2026-0004', scanner: 'grype', state: 'fixed' },
      ]),
    );
    expect(report).toContain('fix-state=conflict (grype=fixed)');
  });

  it('names EVERY scanner behind the verdict, space-separated', () => {
    // Which scanner disagreed is the whole point of the column — "conflict" alone
    // sends the reader back to two 86 MB-scale databases. With both claims present
    // the detail must stay two readable tokens, not `grype=fixedtrivy=will_not_fix`.
    const report = renderReport(
      DEBIAN_SUITE,
      classifyTriples(INDEX, [
        {
          path: '.vex/CVE-2026-0004.openvex.json',
          cve: 'CVE-2026-0004',
          name: 'libnode115',
          version: '20.19.2+dfsg-1+deb13u2',
          purl: 'pkg:deb/debian/libnode115@20.19.2+dfsg-1+deb13u2',
        },
      ]),
      fixStateIndex([
        { id: 'CVE-2026-0004', scanner: 'grype', state: 'fixed' },
        { id: 'CVE-2026-0004', scanner: 'trivy', state: 'will_not_fix' },
      ]),
    );
    expect(report).toContain(
      'fix-state=conflict (grype=fixed trivy=will_not_fix)',
    );
  });

  it('prints Debian’s no-DSA prose AND its short reason on the row', () => {
    // Both fields reach the artifact: the prose says what Debian decided, the
    // reason says why it was allowed to defer. A NO-DSA acceptance is re-reviewed
    // off this row (#353), so a field resolved but not printed is a field the
    // reviewer does not have.
    const report = renderReport(
      DEBIAN_SUITE,
      classifyTriples(INDEX, [
        {
          path: '.vex/CVE-2026-0001.openvex.json',
          cve: 'CVE-2026-0001',
          name: 'libacl1',
          version: '2.3.2-2+b1',
          purl: 'pkg:deb/debian/libacl1@2.3.2-2+b1',
        },
      ]),
      fixStateIndex([]),
    );
    expect(report).toContain(
      'nodsa=Minor issue; fixed via a point release nodsa-reason=postponed',
    );
    expect(report).toContain('| NO-DSA |');
  });

  it('renders an empty ledger without inventing rows', () => {
    const report = renderReport(DEBIAN_SUITE, [], fixStateIndex([]));
    expect(report).toContain('triples: 0');
    expect(report).toContain('  NO-DSA              0');
    expect(report).not.toContain('pkg:deb/debian');
  });
});
