import { readdirSync } from 'node:fs';
import * as path from 'node:path';
import {
  asArray,
  asRecord,
  normId,
  statementIds,
  revisitDate,
  isCalendarDate,
  isRevisitOverdue,
  recordIds,
  activeRecordIds,
  parsePurl,
  purlMatches,
  statementPurls,
  recordAcceptances,
  isCovered,
  isVexRecordName,
  vexRecordPaths,
  statementName,
  recordRevisitBy,
  ledgerRecords,
} from '../../.github/scripts/vex-ledger';

// Unit tests for .github/scripts/vex-ledger.ts (issue #295): the SHARED VEX
// ledger core. Extracts the identifier-matching that was independently
// re-implemented across grype-fs-gate.ts (CVE∪GHSA union) and the dialect
// generators (CVE-only regex) into ONE matcher, so every scanner surface
// (grype FS, trivy, OSV, SARIF, and the new npm-audit gate) agrees on which
// ids a `.vex/` record accepts. Adds the dated-`revisit_by` EXPIRY mechanism
// (the `.nsprc`-parity self-expiry decided on #295): an acceptance whose
// record carries a dated `revisit_by` on/before today stops covering, so the
// finding re-reds automatically instead of rotting silently.
//
// #337 adds the OTHER half of "what does a record cover": the product PURL it
// argues about. Identifier matching alone let an image-scoped `pkg:deb/...`
// record suppress a same-CVE finding on the repo tree's `pkg:npm/...` copy. The
// purl parser is hand-rolled (the grype-FS gate runs on a bare checkout with no
// `npm ci`, so no library is importable there — see the module header), so it is
// held to the purl spec's OWN conformance suite below, and every failure mode is
// fail-closed: an unparseable record purl makes the record inert (the gate reds),
// an unparseable finding purl makes it uncovered (the finding surfaces).
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124),
// Stryker mutation (#122), and the fuzz-regression tier's totality guarantee.

// -- small total coercions (identical contract to grype-fs-gate's copies; this
//    module is where they consolidate) --
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
    expect(normId('cve-2026-13149')).toBe('CVE-2026-13149');
    expect(normId('  ghsa-3jxr-9vmj-r5cp  ')).toBe('GHSA-3JXR-9VMJ-R5CP');
  });
  it('returns null for non-strings and empty/whitespace', () => {
    expect(normId(null)).toBeNull();
    expect(normId(123)).toBeNull();
    expect(normId('')).toBeNull();
    expect(normId('   ')).toBeNull();
    expect(normId(['CVE-2026-13149'])).toBeNull();
  });
});

describe('statementIds', () => {
  it('collects the normalized name AND every alias of one statement', () => {
    expect(
      statementIds({
        vulnerability: {
          name: 'cve-2026-13149',
          aliases: ['GHSA-3jxr-9vmj-r5cp'],
        },
        status: 'affected',
      }),
    ).toEqual(['CVE-2026-13149', 'GHSA-3JXR-9VMJ-R5CP']);
  });
  it('yields the name alone when aliases are absent', () => {
    expect(statementIds({ vulnerability: { name: 'CVE-2005-2541' } })).toEqual([
      'CVE-2005-2541',
    ]);
  });
  it('skips a missing/blank name but keeps usable aliases', () => {
    expect(
      statementIds({ vulnerability: { aliases: ['GHSA-aaaa-bbbb-cccc', ''] } }),
    ).toEqual(['GHSA-AAAA-BBBB-CCCC']);
  });
  it('returns [] for a non-record statement or missing vulnerability', () => {
    expect(statementIds('nope')).toEqual([]);
    expect(statementIds(42)).toEqual([]);
    expect(statementIds(null)).toEqual([]);
    expect(statementIds({})).toEqual([]);
    expect(statementIds({ vulnerability: 'nope' })).toEqual([]);
  });
  it('tolerates a non-array aliases field', () => {
    expect(
      statementIds({ vulnerability: { name: 'CVE-2026-1', aliases: 7 } }),
    ).toEqual(['CVE-2026-1']);
  });
});

describe('revisitDate', () => {
  it('extracts a UTC Date when the string embeds an ISO calendar date', () => {
    const d = revisitDate('revisit 2026-10-01');
    expect(d).toBeInstanceOf(Date);
    expect(d?.toISOString()).toBe('2026-10-01T00:00:00.000Z');
  });
  it('returns undefined for the event-token vocabulary (no date)', () => {
    expect(revisitDate('wait-for-image-rebuild')).toBeUndefined();
    expect(
      revisitDate('waiting-on-upstream-issue https://x/1'),
    ).toBeUndefined();
  });
  it('returns undefined for non-strings', () => {
    expect(revisitDate(undefined)).toBeUndefined();
    expect(revisitDate(null)).toBeUndefined();
    expect(revisitDate(20261001)).toBeUndefined();
  });
  it('returns undefined for a structurally-ISO but invalid calendar date', () => {
    // matches the regex but `new Date` yields Invalid Date
    expect(revisitDate('2026-13-45')).toBeUndefined();
  });
});

describe('isCalendarDate', () => {
  it('accepts a real calendar day in exactly YYYY-MM-DD form', () => {
    expect(isCalendarDate('2026-11-24')).toBe(true);
    expect(isCalendarDate('2024-02-29')).toBe(true); // real leap day
  });
  // The whole reason this predicate exists: `new Date` rolls an overflowing DAY
  // forward instead of rejecting it, so `revisitDate` alone (whose only guard is
  // Invalid-Date) accepts `2026-02-30` as 2026-03-02.
  it('rejects a day that overflows its month (which `new Date` silently rolls over)', () => {
    expect(revisitDate('2026-02-30')?.toISOString()).toBe(
      '2026-03-02T00:00:00.000Z',
    );
    expect(isCalendarDate('2026-02-30')).toBe(false);
    expect(isCalendarDate('2026-04-31')).toBe(false);
    expect(isCalendarDate('2026-02-29')).toBe(false); // 2026 is not a leap year
  });
  it('rejects an out-of-range month/day (Invalid Date)', () => {
    expect(isCalendarDate('2026-13-45')).toBe(false);
    expect(isCalendarDate('2026-00-10')).toBe(false);
  });
  it('rejects anything that is not exactly a bare ISO date', () => {
    expect(isCalendarDate('soon')).toBe(false);
    expect(isCalendarDate('2026-11-24T00:00:00Z')).toBe(false);
    expect(isCalendarDate('revisit 2026-11-24')).toBe(false);
    expect(isCalendarDate('x2026-11-24')).toBe(false);
    expect(isCalendarDate('2026-11-24x')).toBe(false);
  });
});

describe('isRevisitOverdue', () => {
  const today = new Date('2026-07-22T12:00:00.000Z');
  it('is true when a dated revisit_by is strictly before today', () => {
    expect(isRevisitOverdue('revisit 2026-01-01', today)).toBe(true);
  });
  it('is true when a dated revisit_by falls on today (on/before)', () => {
    // 2026-07-22T00:00Z <= 2026-07-22T12:00Z
    expect(isRevisitOverdue('2026-07-22', today)).toBe(true);
  });
  it('is true at the exact instant (revisit == now) — the <= boundary', () => {
    // revisit_by parses to UTC midnight; comparing at the SAME instant proves
    // the comparison is `<=` not `<` (an overdue-on-the-dot record must expire).
    const midnight = new Date('2026-07-22T00:00:00.000Z');
    expect(isRevisitOverdue('2026-07-22', midnight)).toBe(true);
  });
  it('is false when a dated revisit_by is in the future', () => {
    expect(isRevisitOverdue('2026-10-01', today)).toBe(false);
  });
  it('is false for the event-token vocabulary (never expires)', () => {
    expect(isRevisitOverdue('wait-for-image-rebuild', today)).toBe(false);
  });
  it('is false for non-strings and an invalid date', () => {
    expect(isRevisitOverdue(undefined, today)).toBe(false);
    expect(isRevisitOverdue('2026-13-45', today)).toBe(false);
  });
});

describe('recordIds', () => {
  function doc(
    name: string,
    aliases: string[],
    extra: Record<string, unknown> = {},
  ): unknown {
    return {
      '@context': 'https://openvex.dev/ns/v0.2.0',
      statements: [{ vulnerability: { name, aliases }, status: 'affected' }],
      ...extra,
    };
  }

  it('unions the name AND aliases of every statement across all docs', () => {
    const ids = recordIds([
      doc('CVE-2026-13149', ['GHSA-3jxr-9vmj-r5cp']),
      doc('CVE-2005-2541', []),
    ]);
    expect(ids.has('CVE-2026-13149')).toBe(true);
    expect(ids.has('GHSA-3JXR-9VMJ-R5CP')).toBe(true);
    expect(ids.has('CVE-2005-2541')).toBe(true);
    expect(ids.size).toBe(3);
  });
  it('accepts BOTH affected and not_affected records (no status filter)', () => {
    const ids = recordIds([
      doc('CVE-2026-13149', [], { statements: undefined }),
      {
        statements: [
          { vulnerability: { name: 'CVE-1' }, status: 'not_affected' },
          { vulnerability: { name: 'CVE-2' }, status: 'affected' },
        ],
      },
    ]);
    expect(ids.has('CVE-1')).toBe(true);
    expect(ids.has('CVE-2')).toBe(true);
  });
  it('ignores a dated revisit_by (no expiry filtering here)', () => {
    const ids = recordIds([
      doc('CVE-EXPIRED', [], { revisit_by: '2000-01-01' }),
    ]);
    expect(ids.has('CVE-EXPIRED')).toBe(true);
  });
  it('is total on malformed input (non-array, null docs, bad statements)', () => {
    expect(recordIds(undefined as unknown as unknown[]).size).toBe(0);
    expect(recordIds('x' as unknown as unknown[]).size).toBe(0);
    expect(recordIds([null, 42, { statements: 'nope' }]).size).toBe(0);
  });
});

// -- SURFACE SCOPING (#337): the product purl a record actually argues about --
//
// The over-suppression these tests lock out: matching a finding to a record by
// IDENTIFIER ALONE let an image-scoped `pkg:deb/...` record silently suppress a
// same-CVE finding on the repo tree's `pkg:npm/...` copy — the one direction this
// repo's posture forbids (#335 C2, nothing may get quieter).

describe('parsePurl — purl-spec conformance (required, test_type: parse)', () => {
  // Replayed VERBATIM from the purl spec's own conformance suite,
  // package-url/purl-spec `tests/spec/specification-test.json`: every
  // `test_group: required` / `test_type: parse` case, all of which the suite
  // marks `expected_failure: true`. This is the authority the hand-rolled parser
  // is measured against (the CI grype job has no `npm ci`, so a purl library is
  // not importable there — see the module header).
  it.each([
    ['a scheme is always required', 'EnterpriseLibrary.Common@6.0.1304'],
    ['a type is always required', 'pkg:EnterpriseLibrary.Common@6.0.1304'],
    ['check for invalid character in type', 'pkg:n&g?inx/nginx@0.8.9'],
    ['check for type that starts with number', 'pkg:3nginx/nginx@0.8.9'],
    ['check for colon in type', 'pkg:nginx:a/nginx@0.8.9'],
    [
      'checks for invalid qualifier keys',
      'pkg:npm/myartifact@1.0.0?in%20production=true',
    ],
    ['a name is required', 'pkg:maven/@1.3.4'],
    [
      'invalid encoded colon : between scheme and type',
      'pkg%3Amaven/org.apache.commons/io',
    ],
  ])('rejects (%s)', (_description, input) => {
    expect(parsePurl(input)).toBeNull();
  });

  it('accepts the suite’s valid round-trip case (multi-checksum qualifier)', () => {
    // The suite's `validate` case: a versionless purl whose qualifier value is
    // percent-encoded (`%2C` → `,`).
    expect(
      parsePurl(
        'pkg:generic/bitwarderl?checksum=sha1:ad9503c3e994a4f%2Csha256:41bf9088b3a1e6c1ef1d',
      ),
    ).toEqual({
      type: 'generic',
      namespace: '',
      name: 'bitwarderl',
      version: '',
      qualifiers: new Map([
        ['checksum', 'sha1:ad9503c3e994a4f,sha256:41bf9088b3a1e6c1ef1d'],
      ]),
    });
  });
});

describe('parsePurl', () => {
  it('parses the two shapes this repo actually compares (npm lockfile, deb image)', () => {
    expect(parsePurl('pkg:npm/brace-expansion@2.0.1')).toEqual({
      type: 'npm',
      namespace: '',
      name: 'brace-expansion',
      version: '2.0.1',
      qualifiers: new Map(),
    });
    // A Debian version carries `+` (percent-encoded `%2B`) and `~`; decoding must
    // NOT turn `+` into a space (form decoding would), or the record and the
    // scanner would normalize to different versions.
    expect(
      parsePurl(
        'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2?arch=all&distro=debian-13',
      ),
    ).toEqual({
      type: 'deb',
      namespace: 'debian',
      name: 'node-brace-expansion',
      version: '2.0.1+~1.1.0-2',
      qualifiers: new Map([
        ['arch', 'all'],
        ['distro', 'debian-13'],
      ]),
    });
  });

  it('keeps an npm scope as the namespace (the version is the LAST @)', () => {
    expect(parsePurl('pkg:npm/@scope/pkg@1.0.0')).toEqual({
      type: 'npm',
      namespace: '@scope',
      name: 'pkg',
      version: '1.0.0',
      qualifiers: new Map(),
    });
  });

  it('treats the scheme as case-insensitive and trims surrounding whitespace', () => {
    expect(parsePurl('  PKG:npm/x@1.0.0  ')?.name).toBe('x');
    // …but nothing after the scheme is case-folded (a documented deviation: a
    // case-mismatched record fails to cover, which is the loud direction).
    expect(parsePurl('pkg:NPM/X@1.0.0')).toEqual({
      type: 'npm',
      namespace: '',
      name: 'X',
      version: '1.0.0',
      qualifiers: new Map(),
    });
  });

  it('discards the subpath and percent-decodes namespace/name/version', () => {
    expect(parsePurl('pkg:golang/github.com/a/b@v1.2.3#/sub/path')).toEqual({
      type: 'golang',
      namespace: 'github.com/a',
      name: 'b',
      version: 'v1.2.3',
      qualifiers: new Map(),
    });
    expect(parsePurl('pkg:npm/a%2Fb@1%2E0')).toEqual({
      type: 'npm',
      namespace: '',
      name: 'a/b',
      version: '1.0',
      qualifiers: new Map(),
    });
  });

  it('accepts a versionless purl (an empty version is a pattern wildcard)', () => {
    expect(parsePurl('pkg:pypi/ecdsa')).toEqual({
      type: 'pypi',
      namespace: '',
      name: 'ecdsa',
      version: '',
      qualifiers: new Map(),
    });
  });

  it('accepts the legal type charset (letters, digits, . + -)', () => {
    expect(parsePurl('pkg:my-type.x+9/name@1')?.type).toBe('my-type.x+9');
  });

  it('rejects the leading-slash form rather than normalizing it', () => {
    // `pkg://npm/x` is tolerated by the spec but REJECTED here (documented
    // deviation): as a record purl it goes inert, as a finding purl it is
    // unprovable — both fail-closed.
    expect(parsePurl('pkg://npm/x@1.0.0')).toBeNull();
  });

  it('rejects a NON-pkg scheme whose remainder would otherwise parse', () => {
    // The sharp case for the scheme check: most junk is rejected later anyway
    // (blindly dropping four characters usually breaks the rest of the parse), so
    // the only inputs that prove the check runs at all are 4-character schemes
    // whose body IS a valid purl. Without these, dropping the scheme check
    // entirely would be undetectable — and `deb:npm/...` would be read as an npm
    // purl, i.e. one ecosystem's identifier silently matching another's.
    expect(parsePurl('deb:npm/lodash@1.0.0')).toBeNull();
    expect(parsePurl('oci:deb/debian/x@1')).toBeNull();
  });

  it('rejects a non-string, a bare scheme, and a type with no path', () => {
    expect(parsePurl(undefined)).toBeNull();
    expect(parsePurl(null)).toBeNull();
    expect(parsePurl(42)).toBeNull();
    expect(parsePurl(['pkg:npm/x'])).toBeNull();
    expect(parsePurl('')).toBeNull();
    expect(parsePurl('pkg:')).toBeNull();
    expect(parsePurl('pkg:npm')).toBeNull();
    expect(parsePurl('pkg:npm/')).toBeNull(); // no name segment
    expect(parsePurl('pkg:npm/@1.0.0')).toBeNull(); // version only, no name
  });

  it('degrades a malformed percent-escape to raw text instead of throwing', () => {
    // decodeURIComponent throws on `%zz`; both sides of a comparison must still
    // normalize identically, so the raw text is kept.
    expect(parsePurl('pkg:npm/a%zz@1%zz')).toEqual({
      type: 'npm',
      namespace: '',
      name: 'a%zz',
      version: '1%zz',
      qualifiers: new Map(),
    });
  });

  describe('qualifiers', () => {
    it('lower-cases keys, decodes values, and keeps an EMPTY value', () => {
      // Keeping an empty value is a deliberate deviation from packageurl-go
      // (which drops it): dropping widens the pattern, keeping can only narrow.
      expect(parsePurl('pkg:npm/x@1?Arch=x86%5F64&Empty=')?.qualifiers).toEqual(
        new Map([
          ['arch', 'x86_64'],
          ['empty', ''],
        ]),
      );
    });
    it('accepts the legal key charset (letters, digits, . _ -)', () => {
      expect(parsePurl('pkg:npm/x@1?a.b-c_d9=1')?.qualifiers).toEqual(
        new Map([['a.b-c_d9', '1']]),
      );
    });
    it('skips an empty segment and a key with no value (no constraint)', () => {
      expect(parsePurl('pkg:npm/x@1?')?.qualifiers).toEqual(new Map());
      expect(parsePurl('pkg:npm/x@1?a=1&&b&c=2')?.qualifiers).toEqual(
        new Map([
          ['a', '1'],
          ['c', '2'],
        ]),
      );
    });
    it('rejects the whole purl on an out-of-charset or empty key', () => {
      expect(parsePurl('pkg:npm/x@1?a b=1')).toBeNull();
      expect(parsePurl('pkg:npm/x@1?a%20b=1')).toBeNull();
      expect(parsePurl('pkg:npm/x@1?=1')).toBeNull();
      expect(parsePurl('pkg:npm/x@1?a=1&b!=2')).toBeNull();
    });
  });
});

describe('purlMatches (record purl = PATTERN, finding purl = component)', () => {
  const purl = (s: string) => {
    const p = parsePurl(s);
    if (p === null) throw new Error(`unparseable test purl: ${s}`);
    return p;
  };

  it('matches an identical purl', () => {
    expect(purlMatches(purl('pkg:npm/x@1.0.0'), purl('pkg:npm/x@1.0.0'))).toBe(
      true,
    );
  });

  it('requires type, namespace and name to be equal', () => {
    expect(purlMatches(purl('pkg:npm/x@1'), purl('pkg:pypi/x@1'))).toBe(false);
    expect(
      purlMatches(purl('pkg:deb/debian/x@1'), purl('pkg:deb/ubuntu/x@1')),
    ).toBe(false);
    expect(purlMatches(purl('pkg:deb/debian/x@1'), purl('pkg:deb/x@1'))).toBe(
      false,
    );
    expect(purlMatches(purl('pkg:npm/x@1'), purl('pkg:npm/y@1'))).toBe(false);
  });

  it('requires a SET pattern version to match exactly', () => {
    expect(purlMatches(purl('pkg:npm/x@1.0.0'), purl('pkg:npm/x@1.0.1'))).toBe(
      false,
    );
    expect(purlMatches(purl('pkg:npm/x@1.0.0'), purl('pkg:npm/x'))).toBe(false);
  });

  it('treats an EMPTY pattern version as a wildcard', () => {
    expect(purlMatches(purl('pkg:npm/x'), purl('pkg:npm/x@1.0.0'))).toBe(true);
    expect(purlMatches(purl('pkg:npm/x'), purl('pkg:npm/x'))).toBe(true);
    // …but not the reverse: a versionless FINDING is not covered by a versioned
    // record (the pattern is allowed to be broader, never the component).
    expect(purlMatches(purl('pkg:npm/x@1.0.0'), purl('pkg:npm/x'))).toBe(false);
  });

  it('is qualifier-INSENSITIVE: qualifiers the pattern omits are ignored', () => {
    // Exactly why .vex/README.md mandates qualifier-less product purls — grype
    // and trivy emit different arch/distro/epoch qualifiers for one package.
    expect(
      purlMatches(
        purl('pkg:deb/debian/x@1'),
        purl('pkg:deb/debian/x@1?arch=all&distro=debian-13&epoch=1'),
      ),
    ).toBe(true);
  });

  it('requires every qualifier the pattern DOES name to be present and equal', () => {
    // The POSITIVE direction first: a pattern qualifier that IS present and equal
    // must still match (extra component qualifiers remain ignored). Without this
    // case "reject on any named qualifier" would be indistinguishable from the
    // real rule — the subset relation would collapse to an equality test and a
    // legitimately-qualified record would silently go inert.
    expect(
      purlMatches(
        purl('pkg:deb/debian/x@1?arch=all'),
        purl('pkg:deb/debian/x@1?arch=all&distro=debian-13'),
      ),
    ).toBe(true);
    expect(
      purlMatches(
        purl('pkg:deb/debian/x@1?arch=all'),
        purl('pkg:deb/debian/x@1?arch=amd64'),
      ),
    ).toBe(false);
    expect(
      purlMatches(
        purl('pkg:deb/debian/x@1?arch=all'),
        purl('pkg:deb/debian/x@1'),
      ),
    ).toBe(false);
    expect(
      purlMatches(
        purl('pkg:deb/debian/x@1?arch=all&distro=debian-13'),
        purl('pkg:deb/debian/x@1?arch=all'),
      ),
    ).toBe(false);
  });
});

describe('statementPurls', () => {
  it('reads both `@id` and `identifiers.purl` of every product', () => {
    const purls = statementPurls({
      vulnerability: { name: 'CVE-1' },
      products: [
        {
          '@id': 'pkg:pypi/mcp@1.23.3',
          identifiers: { purl: 'pkg:pypi/mcp@1.23.3' },
        },
        { '@id': 'pkg:npm/x@1.0.0' },
        { identifiers: { purl: 'pkg:npm/y@2.0.0' } },
      ],
    });
    expect(purls.map((p) => `${p.type}/${p.name}@${p.version}`)).toEqual([
      'pypi/mcp@1.23.3',
      'pypi/mcp@1.23.3',
      'npm/x@1.0.0',
      'npm/y@2.0.0',
    ]);
  });

  it('drops unparseable and non-purl product identifiers', () => {
    expect(
      statementPurls({
        products: [
          { '@id': 'https://example.invalid/not-a-purl' },
          { '@id': 42, identifiers: { purl: null } },
          { '@id': 'pkg:npm/keep@1' },
        ],
      }).map((p) => p.name),
    ).toEqual(['keep']);
  });

  it('is total on malformed input (non-record statement/products/product)', () => {
    expect(statementPurls(null)).toEqual([]);
    expect(statementPurls('nope')).toEqual([]);
    expect(statementPurls({})).toEqual([]);
    expect(statementPurls({ products: 'nope' })).toEqual([]);
    expect(statementPurls({ products: [null, 42, []] })).toEqual([]);
    expect(statementPurls({ products: [{ identifiers: 'nope' }] })).toEqual([]);
  });

  it('does NOT read subcomponents (a record must name its product directly)', () => {
    // .vex/README.md mandates the direct product-purl shape; a purl nested under
    // `subcomponents` yields nothing here, so the record goes inert and the gate
    // reds — a loud authoring failure rather than a silent broad match.
    expect(
      statementPurls({
        products: [
          {
            '@id': 'not-a-purl',
            subcomponents: [{ '@id': 'pkg:npm/x@1.0.0' }],
          },
        ],
      }),
    ).toEqual([]);
  });
});

describe('recordAcceptances', () => {
  const MCP = 'pkg:pypi/mcp@1.23.3';
  function doc(name: string, purl: string | undefined, status = 'affected') {
    return {
      statements: [
        {
          vulnerability: { name, aliases: ['GHSA-aaaa-bbbb-cccc'] },
          ...(purl === undefined
            ? {}
            : { products: [{ '@id': purl, identifiers: { purl } }] }),
          status,
        },
      ],
    };
  }

  it('pairs each statement’s ids with the purls it argues about', () => {
    const [acceptance, ...rest] = recordAcceptances([doc('CVE-1', MCP)]);
    expect(rest).toEqual([]);
    expect([...acceptance.ids]).toEqual(['CVE-1', 'GHSA-AAAA-BBBB-CCCC']);
    expect(acceptance.purls.map((p) => p.name)).toEqual(['mcp', 'mcp']);
  });

  it('accepts BOTH affected and not_affected statements (#188 status honesty)', () => {
    expect(recordAcceptances([doc('CVE-1', MCP, 'affected')])).toHaveLength(1);
    expect(recordAcceptances([doc('CVE-2', MCP, 'not_affected')])).toHaveLength(
      1,
    );
  });

  it('emits ONE acceptance PER STATEMENT (products live on the statement)', () => {
    const acceptances = recordAcceptances([
      {
        statements: [
          {
            vulnerability: { name: 'CVE-1' },
            products: [{ '@id': 'pkg:npm/a@1' }],
          },
          {
            vulnerability: { name: 'CVE-2' },
            products: [{ '@id': 'pkg:npm/b@1' }],
          },
        ],
      },
    ]);
    expect(acceptances).toHaveLength(2);
    expect(acceptances.map((a) => a.purls[0]?.name)).toEqual(['a', 'b']);
  });

  it('FAIL-CLOSED: a statement with no product purl yields NO acceptance', () => {
    // The whole point of #337 — an acceptance with no provable surface must be
    // inert, not universal. It cannot suppress anything anywhere.
    expect(recordAcceptances([doc('CVE-1', undefined)])).toEqual([]);
    expect(
      recordAcceptances([doc('CVE-1', 'https://example.invalid/nope')]),
    ).toEqual([]);
  });

  it('FAIL-CLOSED: a statement with no matchable id yields NO acceptance', () => {
    expect(
      recordAcceptances([
        { statements: [{ products: [{ '@id': MCP }], status: 'affected' }] },
      ]),
    ).toEqual([]);
  });

  it('is total on malformed input (non-array, null docs, bad statements)', () => {
    expect(recordAcceptances(undefined as unknown as unknown[])).toEqual([]);
    expect(recordAcceptances('x' as unknown as unknown[])).toEqual([]);
    expect(recordAcceptances([null, 42, { statements: 'nope' }])).toEqual([]);
    expect(recordAcceptances([{ statements: [null, 7] }])).toEqual([]);
  });
});

describe('isCovered (the shared coverage decision)', () => {
  const MCP = 'pkg:pypi/mcp@1.23.3';
  const acceptances = recordAcceptances([
    {
      statements: [
        {
          vulnerability: {
            name: 'CVE-2026-52869',
            aliases: ['GHSA-jpw9-pfvf-9f58'],
          },
          products: [{ '@id': MCP, identifiers: { purl: MCP } }],
          status: 'affected',
        },
      ],
    },
    {
      statements: [
        {
          vulnerability: { name: 'CVE-2026-13149' },
          products: [
            { '@id': 'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2' },
          ],
          status: 'not_affected',
        },
      ],
    },
  ]);
  const findingPurl = (s: string) => parsePurl(s);

  it('covers a finding when an id AND the purl agree', () => {
    expect(
      isCovered(acceptances, new Set(['CVE-2026-52869']), findingPurl(MCP)),
    ).toBe(true);
    // …including via an alias (grype may name only the GHSA).
    expect(
      isCovered(
        acceptances,
        new Set(['GHSA-JPW9-PFVF-9F58']),
        findingPurl(MCP),
      ),
    ).toBe(true);
  });

  it('does NOT cover a matching id on a DIFFERENT surface (#337)', () => {
    expect(
      isCovered(
        acceptances,
        new Set(['CVE-2026-13149']),
        findingPurl('pkg:npm/brace-expansion@2.0.1'),
      ),
    ).toBe(false);
    // …while the record still covers the image package it was written for, whose
    // scanner-emitted purl carries extra qualifiers.
    expect(
      isCovered(
        acceptances,
        new Set(['CVE-2026-13149']),
        findingPurl(
          'pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2?arch=all&distro=debian-13',
        ),
      ),
    ).toBe(true);
  });

  it('does NOT cover a matching purl under an unrelated id', () => {
    expect(
      isCovered(acceptances, new Set(['CVE-2099-99999']), findingPurl(MCP)),
    ).toBe(false);
  });

  it('requires the id and the purl to come from the SAME acceptance', () => {
    // An id from the mcp record plus a purl from the deb record proves nothing.
    expect(
      isCovered(
        acceptances,
        new Set(['CVE-2026-52869']),
        findingPurl('pkg:deb/debian/node-brace-expansion@2.0.1%2B~1.1.0-2'),
      ),
    ).toBe(false);
  });

  it('never covers a finding with NO parseable purl (fail-closed)', () => {
    expect(isCovered(acceptances, new Set(['CVE-2026-52869']), null)).toBe(
      false,
    );
  });

  it('covers nothing when there are no acceptances, or no finding ids', () => {
    expect(isCovered([], new Set(['CVE-2026-52869']), findingPurl(MCP))).toBe(
      false,
    );
    expect(isCovered(acceptances, new Set(), findingPurl(MCP))).toBe(false);
  });
});

describe('activeRecordIds', () => {
  const today = new Date('2026-07-22T12:00:00.000Z');
  function doc(name: string, revisit_by?: string): unknown {
    return {
      statements: [{ vulnerability: { name }, status: 'affected' }],
      ...(revisit_by === undefined ? {} : { revisit_by }),
    };
  }

  it('includes ids from records with no revisit_by', () => {
    const ids = activeRecordIds([doc('CVE-LIVE')], today);
    expect(ids.has('CVE-LIVE')).toBe(true);
  });
  it('includes ids from records whose dated revisit_by is in the future', () => {
    const ids = activeRecordIds([doc('CVE-FUTURE', '2026-10-01')], today);
    expect(ids.has('CVE-FUTURE')).toBe(true);
  });
  it('includes ids from event-token records (never expire)', () => {
    const ids = activeRecordIds(
      [doc('CVE-EVENT', 'wait-for-image-rebuild')],
      today,
    );
    expect(ids.has('CVE-EVENT')).toBe(true);
  });
  it('EXCLUDES ids from records whose dated revisit_by is overdue', () => {
    const ids = activeRecordIds([doc('CVE-STALE', '2026-01-01')], today);
    expect(ids.has('CVE-STALE')).toBe(false);
    expect(ids.size).toBe(0);
  });
  it('drops only the overdue doc, keeping live docs in the same set', () => {
    const ids = activeRecordIds(
      [doc('CVE-STALE', '2026-01-01'), doc('CVE-LIVE')],
      today,
    );
    expect(ids.has('CVE-STALE')).toBe(false);
    expect(ids.has('CVE-LIVE')).toBe(true);
    expect(ids.size).toBe(1);
  });
  it('is total on malformed input', () => {
    expect(activeRecordIds(undefined as unknown as unknown[], today).size).toBe(
      0,
    );
    expect(activeRecordIds([null, 42], today).size).toBe(0);
  });
});

// -- LEDGER DISCOVERY + RECORD PROJECTION (#342) --
//
// The drift these tests lock out: discovery of `.vex/` records was
// re-implemented in each `.mjs` shim, and the two copies disagreed.
// `vex-report.mjs` filtered `startsWith('CVE-') && endsWith('.openvex.json')`
// while `vex-dialects.mjs` filtered the suffix alone — so over ONE directory the
// report silently read 46 of the 48 committed records, dropping exactly the
// surface-prefixed ones (`ecdsa-…`, `pytest-…`). Those two are the only records
// carrying a DATED `revisit_by`, so the report's whole `Revisit overdue`
// pathway was unreachable. A prefix is a SCOPE claim (which scanner surface the
// record argues about — see `purlMatches` above); it is never a discovery
// filter. These live here, not in the shims, because per #165 the shims are
// invisible to the coverage (#124) and mutation (#122) gates.

describe('isVexRecordName', () => {
  it('accepts a record whatever its surface prefix', () => {
    expect(isVexRecordName('CVE-2026-13149.openvex.json')).toBe(true);
    expect(isVexRecordName('ecdsa-CVE-2024-23342.openvex.json')).toBe(true);
    expect(isVexRecordName('pytest-CVE-2025-71176.openvex.json')).toBe(true);
    expect(isVexRecordName('npm-GHSA-6v5v-wf23-fmfq.openvex.json')).toBe(true);
  });
  it('rejects a filename that is not a record', () => {
    expect(isVexRecordName('README.md')).toBe(false);
    expect(isVexRecordName('CVE-2026-13149.json')).toBe(false);
    expect(isVexRecordName('CVE-2026-13149.openvex.json.bak')).toBe(false);
    expect(isVexRecordName('openvex.json')).toBe(false);
  });
  it('is total on non-strings', () => {
    expect(isVexRecordName(undefined)).toBe(false);
    expect(isVexRecordName(null)).toBe(false);
    expect(isVexRecordName(42)).toBe(false);
  });
});

describe('vexRecordPaths', () => {
  it('returns every record as a dir-joined, sorted path — prefix-agnostic', () => {
    expect(
      vexRecordPaths(
        [
          'pytest-CVE-2025-71176.openvex.json',
          'CVE-2005-2541.openvex.json',
          'README.md',
        ],
        '.vex',
      ),
    ).toEqual([
      '.vex/CVE-2005-2541.openvex.json',
      '.vex/pytest-CVE-2025-71176.openvex.json',
    ]);
  });
  it('is total on a non-array listing and on non-string entries', () => {
    expect(vexRecordPaths(undefined as unknown as unknown[], '.vex')).toEqual(
      [],
    );
    expect(vexRecordPaths([null, 42, {}], '.vex')).toEqual([]);
  });
  it('reads EVERY committed record in the real `.vex/` ledger (#342)', () => {
    // The acceptance criterion for #342: the loaded count equals the on-disk
    // count. Both sides are derived from the same listing (never a transcribed
    // number), so this stays true as the ledger grows — but it fails the instant
    // a prefix filter is reintroduced, because the ledger carries
    // surface-prefixed records today.
    const dir = path.resolve(__dirname, '../../.vex');
    const listing = readdirSync(dir);
    const onDisk = listing.filter((name) => /\.openvex\.json$/.test(name));
    expect(onDisk.length).toBeGreaterThan(0);

    const found = vexRecordPaths(listing, dir);
    expect(found).toHaveLength(onDisk.length);
    for (const name of onDisk.filter((n) => !n.startsWith('CVE-'))) {
      expect(found).toContain(`${dir}/${name}`);
    }
  });
});

describe('statementName', () => {
  it('reads the object form this repo authors, normalized', () => {
    expect(statementName({ vulnerability: { name: ' cve-2026-13149 ' } })).toBe(
      'CVE-2026-13149',
    );
  });
  it('also reads the bare-string form the OpenVEX spec allows', () => {
    expect(statementName({ vulnerability: 'CVE-2005-2541' })).toBe(
      'CVE-2005-2541',
    );
  });
  it('names the vulnerability only — never an alias', () => {
    expect(
      statementName({
        vulnerability: { name: 'CVE-1', aliases: ['GHSA-aaaa-bbbb-cccc'] },
      }),
    ).toBe('CVE-1');
  });
  it('is total: a missing/unusable vulnerability or a non-record yields null', () => {
    expect(statementName({})).toBeNull();
    expect(statementName({ vulnerability: {} })).toBeNull();
    expect(statementName({ vulnerability: { name: 42 } })).toBeNull();
    expect(statementName({ vulnerability: ['CVE-1'] })).toBeNull();
    expect(statementName(null)).toBeNull();
    expect(statementName('nope')).toBeNull();
  });
});

describe('recordRevisitBy', () => {
  it('prefers the DOCUMENT level — where every record in this ledger sets it', () => {
    expect(
      recordRevisitBy(
        { revisit_by: 'revisit 2026-11-24' },
        { revisit_by: '2000-01-01' },
      ),
    ).toBe('revisit 2026-11-24');
  });
  it('falls back to the statement level when the document omits the key', () => {
    expect(recordRevisitBy({}, { revisit_by: 'wait-for-image-rebuild' })).toBe(
      'wait-for-image-rebuild',
    );
    expect(
      recordRevisitBy(null, { revisit_by: 'wait-for-image-rebuild' }),
    ).toBe('wait-for-image-rebuild');
  });
  it('lets an explicit document-level `null` WIN over a statement value', () => {
    // The bug `??` had: it treats an explicit document-level `null` as ABSENT
    // and silently inherits a stale statement-level date.
    expect(
      recordRevisitBy({ revisit_by: null }, { revisit_by: '2000-01-01' }),
    ).toBeUndefined();
  });
  it('is total: a non-string cadence at either level reads as absent', () => {
    expect(recordRevisitBy({ revisit_by: 42 }, {})).toBeUndefined();
    expect(recordRevisitBy({}, { revisit_by: { on: '2000-01-01' } })).toBe(
      undefined,
    );
    expect(recordRevisitBy({}, {})).toBeUndefined();
    expect(recordRevisitBy(null, null)).toBeUndefined();
  });
});

describe('ledgerRecords', () => {
  it('projects one record per statement, carrying the ledger fields through', () => {
    expect(
      ledgerRecords([
        {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: { name: 'CVE-2005-2541' },
              status: 'not_affected',
              justification:
                'vulnerable_code_cannot_be_controlled_by_adversary',
            },
          ],
        },
      ]),
    ).toEqual([
      {
        cve: 'CVE-2005-2541',
        status: 'not_affected',
        justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
        revisitBy: 'wait-for-image-rebuild',
      },
    ]);
  });
  it('reads EVERY statement, not just statements[0]', () => {
    // The shim this replaced read `statements[0]` only, so a multi-statement
    // record had its 2nd..nth acceptances invisible in the report while still
    // suppressing scanner findings.
    expect(
      ledgerRecords([
        {
          statements: [
            { vulnerability: { name: 'CVE-1' }, status: 'not_affected' },
            { vulnerability: { name: 'CVE-2' }, status: 'affected' },
          ],
        },
      ]).map((r) => `${r.cve}:${r.status}`),
    ).toEqual(['CVE-1:not_affected', 'CVE-2:affected']);
  });
  it('resolves revisit_by per statement via recordRevisitBy', () => {
    expect(
      ledgerRecords([
        {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              status: 'affected',
              revisit_by: 'revisit 2026-11-24',
            },
          ],
        },
      ])[0]?.revisitBy,
    ).toBe('revisit 2026-11-24');
  });
  it('reports a missing status as authored (never silently normalized)', () => {
    expect(
      ledgerRecords([{ statements: [{ vulnerability: 'CVE-1' }] }]),
    ).toEqual([
      {
        cve: 'CVE-1',
        status: 'undefined',
        justification: undefined,
        revisitBy: undefined,
      },
    ]);
  });
  it('drops a non-string justification rather than passing it through', () => {
    expect(
      ledgerRecords([
        {
          statements: [
            { vulnerability: { name: 'CVE-1' }, status: 'x', justification: 7 },
          ],
        },
      ])[0]?.justification,
    ).toBeUndefined();
  });
  it('skips a statement with no usable vulnerability id, keeping its siblings', () => {
    expect(
      ledgerRecords([
        {
          statements: [
            { status: 'not_affected' },
            'nope',
            null,
            { vulnerability: { name: 'CVE-KEPT' }, status: 'affected' },
          ],
        },
      ]).map((r) => r.cve),
    ).toEqual(['CVE-KEPT']);
  });
  it('is total on malformed input (non-array, null docs, bad statements)', () => {
    expect(ledgerRecords(undefined as unknown as unknown[])).toEqual([]);
    expect(ledgerRecords([null, 42, { statements: 'nope' }])).toEqual([]);
  });
});
