import {
  SUPPRESSING_STATUSES,
  OSV_SCANNED_PURL_TYPES,
  suppressingRecords,
  osvEmittable,
  ignoredVulns,
  reasonFor,
  ignoreUntilFrom,
  renderTrivyYaml,
  renderOsvToml,
  type VexFile,
} from '../../.github/scripts/vex-dialects';

// Unit tests for .github/scripts/vex-dialects.ts (issue #251):
// `.vex/*.openvex.json` is the ONE canonical ledger; this generator emits each
// scanner's suppression dialect from it — the trivy.yaml `vulnerability.vex`
// FILE list and the osv-scanner.toml `[[IgnoredVulns]]` array — killing the
// hand-maintained parity (trivy.yaml) and adding the missing OSV channel.
//
// Imported IN-PROCESS so it flows through the 100% coverage gate (#124) +
// Stryker mutation (#122) + fuzz-regression tier. Its output is
// security-load-bearing: a dropped record re-opens a VEX-gated scanner, and a
// spuriously-emitted one silences a live finding.
//
// The core invariant (shared with vex-to-sarif-suppressions.ts via the exact
// same `SUPPRESSING_STATUSES` set): only `not_affected`/`fixed` generate a
// suppression in ANY dialect; `affected` NEVER suppresses anywhere (the mcp
// records — #226/#227 — must stay visible in grype/trivy/OSV/Code-Scanning).
//
// The SECOND invariant (#337) is SURFACE SCOPE, and it is why every fixture here
// carries a `products` purl. Trivy scopes a suppression by product purl itself
// (it reads the OpenVEX document), but OSV's `[[IgnoredVulns]]` keys on the
// vulnerability id ALONE — so a row generated for an IMAGE-scoped `pkg:deb/...`
// record could only ever silence a same-CVE finding on the repo TREE. Emission
// is the only lever, hence `osvEmittable`: the deb fixtures below MUST appear in
// the trivy dialect and MUST NOT appear in the OSV one.

// The THIRD reason every fixture below is shaped the way it is (#352): each
// carries a `revisit_by`, because `VexDoc.revisit_by` is no longer optional.
// #336 made the field's presence a hard CI gate, after which `revisit_by?:` was
// simply a false type — no record in the ledger can lack it — and an optional
// field invites callers to tolerate `undefined` that cannot occur. Dropping the
// `?` surfaced every fixture that modelled a record the ledger would reject; each
// now names a sanctioned form, so the fixture corpus is a truthful sample. Where
// the form is DATED it changes behaviour (an OSV `ignoreUntil`), so the
// no-ignoreUntil fixtures deliberately use event/standing forms.

// The three surfaces the fixtures argue about. `@id` is the purl form
// `.vex/README.md` mandates (qualifier-less, canonical); `statementPurls` reads
// it (and `identifiers.purl`) — see vex-ledger.ts.
const DEB_PRODUCTS = [{ '@id': 'pkg:deb/debian/node-brace-expansion' }];
const NPM_PRODUCTS = [{ '@id': 'pkg:npm/some-package' }];
const PYPI_PRODUCTS = [{ '@id': 'pkg:pypi/ecdsa' }];

// A not_affected image-CVE record, shaped like .vex/CVE-*.openvex.json — an
// IMAGE surface (`pkg:deb/...`), which OSV never scans here.
const NA_IMAGE: VexFile = {
  path: '.vex/CVE-2026-11822.openvex.json',
  doc: {
    revisit_by: 'wait-for-image-rebuild',
    statements: [
      {
        vulnerability: { name: 'CVE-2026-11822' },
        status: 'not_affected',
        justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
        impact_statement: 'Accepted risk: local-only CI emulator.',
        products: DEB_PRODUCTS,
      },
    ],
  },
};

// A not_affected FS-surface record (ecdsa-style, pypi purl).
const NA_FS: VexFile = {
  path: '.vex/ecdsa-CVE-2024-23342.openvex.json',
  doc: {
    revisit_by:
      'waiting-on-upstream-issue https://github.com/tlsfuzzer/python-ecdsa/security/advisories/GHSA-wj6h-64fc-37mp',
    statements: [
      {
        vulnerability: { name: 'CVE-2024-23342' },
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        impact_statement: 'Signing path unreachable.',
        products: PYPI_PRODUCTS,
      },
    ],
  },
};

// An `affected` mcp record — must NEVER suppress in any dialect.
const AFFECTED_MCP: VexFile = {
  path: '.vex/mcp-CVE-2026-52869.openvex.json',
  doc: {
    revisit_by:
      'waiting-on-upstream-issue https://github.com/semgrep/semgrep/issues/11506',
    statements: [
      {
        vulnerability: { name: 'CVE-2026-52869' },
        status: 'affected',
        products: PYPI_PRODUCTS,
      },
    ],
  },
};

// A `fixed` record on the npm surface.
const FIXED: VexFile = {
  path: '.vex/CVE-2026-0001.openvex.json',
  doc: {
    revisit_by: 'waiting-for-fix CVE-2026-0001',
    statements: [
      {
        vulnerability: { name: 'CVE-2026-0001' },
        status: 'fixed',
        products: NPM_PRODUCTS,
      },
    ],
  },
};

describe('SUPPRESSING_STATUSES (reused from vex-to-sarif-suppressions)', () => {
  it('is exactly {not_affected, fixed} — the single source of truth', () => {
    expect([...SUPPRESSING_STATUSES].sort()).toEqual(['fixed', 'not_affected']);
  });
});

describe('suppressingRecords', () => {
  it('keeps only records with a not_affected/fixed statement, sorted by path', () => {
    const out = suppressingRecords([AFFECTED_MCP, NA_IMAGE, NA_FS, FIXED]);
    expect(out.map((r) => r.path)).toEqual([
      '.vex/CVE-2026-0001.openvex.json',
      '.vex/CVE-2026-11822.openvex.json',
      '.vex/ecdsa-CVE-2024-23342.openvex.json',
    ]);
  });

  it('EXCLUDES affected records (mcp stays visible in every dialect)', () => {
    const out = suppressingRecords([AFFECTED_MCP]);
    expect(out).toEqual([]);
  });

  it('EXCLUDES under_investigation and missing-status records', () => {
    const out = suppressingRecords([
      {
        path: '.vex/a.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: { name: 'CVE-2026-2' },
              status: 'under_investigation',
            },
          ],
        },
      },
      {
        path: '.vex/b.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [{ vulnerability: { name: 'CVE-2026-3' } }],
        },
      },
    ]);
    expect(out).toEqual([]);
  });

  it('tolerates malformed inputs without throwing (totality)', () => {
    expect(suppressingRecords([])).toEqual([]);
    expect(suppressingRecords(undefined as unknown as VexFile[])).toEqual([]);
    expect(
      suppressingRecords([{ path: '.vex/x.json', doc: {} } as VexFile]),
    ).toEqual([]);
    expect(
      suppressingRecords([
        {
          path: '.vex/x.json',
          doc: { statements: 'nope' },
        } as unknown as VexFile,
      ]),
    ).toEqual([]);
    expect(
      suppressingRecords([
        {
          path: '.vex/x.json',
          doc: { statements: [null] },
        } as unknown as VexFile,
      ]),
    ).toEqual([]);
    // a null file element is skipped
    expect(
      suppressingRecords([null as unknown as VexFile, NA_IMAGE]).map(
        (r) => r.path,
      ),
    ).toEqual(['.vex/CVE-2026-11822.openvex.json']);
  });

  it('does not mutate the caller array order', () => {
    const input = [NA_FS, NA_IMAGE];
    suppressingRecords(input);
    expect(input[0]).toBe(NA_FS); // original array untouched (slice before sort)
  });

  it('keeps both records when two share an identical path (equal-compare branch)', () => {
    // Exercises the sort comparator's `=== 0` (equal) branch: two records with
    // the same path must both survive and stay adjacent.
    const dup: VexFile = {
      path: '.vex/CVE-2026-11822.openvex.json',
      doc: {
        revisit_by: 'wait-for-image-rebuild',
        statements: [
          { vulnerability: { name: 'CVE-2026-11822' }, status: 'fixed' },
        ],
      },
    };
    const out = suppressingRecords([NA_IMAGE, dup]);
    expect(out).toHaveLength(2);
    expect(
      out.every((r) => r.path === '.vex/CVE-2026-11822.openvex.json'),
    ).toBe(true);
  });
});

describe('reasonFor', () => {
  it('combines status + justification enum + impact for a not_affected record', () => {
    const r = reasonFor(NA_IMAGE.doc.statements![0]);
    expect(r).toContain('not_affected');
    expect(r).toContain('vulnerable_code_cannot_be_controlled_by_adversary');
    expect(r).toContain('Accepted risk: local-only CI emulator.');
  });

  it('falls back to a default enum when justification is absent/empty', () => {
    expect(reasonFor({ status: 'not_affected' })).toContain('vex_not_affected');
    expect(reasonFor({ status: 'fixed', justification: '' })).toContain(
      'vex_not_affected',
    );
  });

  it('omits the impact suffix when impact_statement is absent/empty', () => {
    expect(reasonFor({ status: 'fixed', justification: 'j' })).toBe(
      'VEX fixed (j)',
    );
    expect(
      reasonFor({ status: 'fixed', justification: 'j', impact_statement: '' }),
    ).toBe('VEX fixed (j)');
  });
});

describe('ignoreUntilFrom', () => {
  it('extracts an ISO date embedded in a revisit_by string', () => {
    expect(ignoreUntilFrom('revisit 2026-12-31')).toEqual(
      new Date('2026-12-31T00:00:00Z'),
    );
    expect(ignoreUntilFrom('2027-01-15')).toEqual(
      new Date('2027-01-15T00:00:00Z'),
    );
  });

  it('returns undefined for non-date revisit_by vocabulary', () => {
    expect(ignoreUntilFrom('wait-for-image-rebuild')).toBeUndefined();
    expect(
      ignoreUntilFrom('waiting-on-upstream-issue https://x/y'),
    ).toBeUndefined();
    expect(ignoreUntilFrom('waiting-for-fix CVE-2026-13149')).toBeUndefined();
    // The class-C form (#352). `CVE-2026-13149` above is the neighbouring trap:
    // its digits are NOT `YYYY-MM-DD`-shaped, so neither event form yields a
    // spurious self-expiring ignore.
    expect(ignoreUntilFrom('standing-acceptance')).toBeUndefined();
    expect(ignoreUntilFrom(undefined)).toBeUndefined();
    expect(ignoreUntilFrom(42 as unknown as string)).toBeUndefined();
    expect(ignoreUntilFrom('')).toBeUndefined();
  });
});

describe('OSV_SCANNED_PURL_TYPES / osvEmittable (#337 surface scope)', () => {
  // A statement carrying exactly the given product purls.
  const stmt = (...purls: string[]) => ({
    vulnerability: { name: 'CVE-2026-1234' },
    status: 'not_affected',
    products: purls.map((purl) => ({ '@id': purl })),
  });

  it('is exactly {npm, pypi} — the ecosystems the OSV job actually scans', () => {
    // Coupled to the `osv-scanner` job in .github/workflows/security.yml:
    // `--lockfile=package-lock.json` (npm) + the three
    // .github/scanner-requirements/**/requirements.txt files (pypi). Adding a
    // lockfile in a new ecosystem there without adding its purl type here makes
    // a legitimate acceptance stop suppressing — the gate reds, never quietens.
    expect([...OSV_SCANNED_PURL_TYPES].sort()).toEqual(['npm', 'pypi']);
  });

  it('accepts an npm-scoped statement', () => {
    expect(osvEmittable(stmt('pkg:npm/some-package@1.0.0'))).toBe(true);
  });

  it('accepts a pypi-scoped statement', () => {
    expect(osvEmittable(stmt('pkg:pypi/ecdsa@0.19.2'))).toBe(true);
  });

  it('accepts a statement whose several purls are ALL in scope', () => {
    expect(osvEmittable(stmt('pkg:npm/a', 'pkg:pypi/b'))).toBe(true);
  });

  it('REJECTS every surface OSV does not scan here', () => {
    // The image/OS surfaces (deb is the real case — the MiniStack emulator
    // records) plus the container/binary types that a future record might name.
    for (const purl of [
      'pkg:deb/debian/node-brace-expansion@2.0.1',
      'pkg:rpm/redhat/openssl@3.0.7',
      'pkg:apk/alpine/busybox@1.36.1',
      'pkg:oci/ministack@sha256%3Aabc',
      'pkg:generic/openssl@3.0.7',
      'pkg:golang/github.com/x/y@v1.2.3',
    ]) {
      expect(osvEmittable(stmt(purl))).toBe(false);
    }
  });

  it('REJECTS a statement mixing an in-scope purl with an out-of-scope one', () => {
    // `every`, not `some`: one unscanned surface disqualifies the whole
    // statement, because the emitted row would apply to BOTH.
    expect(osvEmittable(stmt('pkg:npm/a', 'pkg:deb/debian/a'))).toBe(false);
    expect(osvEmittable(stmt('pkg:deb/debian/a', 'pkg:npm/a'))).toBe(false);
  });

  it('REJECTS a statement that proves no surface at all (fail-closed)', () => {
    // No products, an empty products array, an unparseable purl, or a purl
    // nested where the ledger does not read it: none proves the surface is in
    // scope, so none is emitted. Not emitting can only make OSV louder.
    expect(osvEmittable({})).toBe(false);
    expect(osvEmittable({ products: [] })).toBe(false);
    expect(osvEmittable(stmt('not-a-purl'))).toBe(false);
    expect(osvEmittable(stmt(''))).toBe(false);
    expect(
      osvEmittable({
        products: [{ subcomponents: [{ '@id': 'pkg:npm/a' }] }],
      }),
    ).toBe(false);
  });

  it('reads the purl from identifiers.purl as well as @id', () => {
    // Both spellings are legal OpenVEX and this repo's records set both; the
    // ledger's shared `statementPurls` is the single reader for grype + OSV.
    expect(
      osvEmittable({
        products: [{ identifiers: { purl: 'pkg:npm/some-package@1.0.0' } }],
      }),
    ).toBe(true);
  });
});

describe('ignoredVulns (OSV [[IgnoredVulns]] rows)', () => {
  it('maps each IN-SCOPE suppressing record to an {id, reason} row, sorted by path', () => {
    const rows = ignoredVulns([AFFECTED_MCP, NA_IMAGE, NA_FS]);
    // NA_IMAGE is deb-scoped (#337) and NOT emitted; AFFECTED_MCP is `affected`
    // (#188) and NOT emitted. Only the pypi record survives.
    expect(rows.map((r) => r.id)).toEqual(['CVE-2024-23342']);
    expect(rows[0].reason).toContain('not_affected');
    expect(rows[0].ignoreUntil).toBeUndefined();
  });

  it('#337: DOES NOT emit a row for an image-scoped (pkg:deb) record', () => {
    // The whole bug: an ignore row keyed on the id ALONE cannot suppress the
    // emulator-image finding it was written for (OSV never scans the image
    // here) — it can only silence the same CVE on the repo TREE. This is the
    // OSV half of #337, and it fails on the pre-fix generator, which emitted
    // every suppressing record regardless of surface.
    expect(ignoredVulns([NA_IMAGE])).toEqual([]);
    // …while the SAME record still reaches trivy, which scopes by purl itself.
    expect(renderTrivyYaml([NA_IMAGE])).toContain(
      '    - .vex/CVE-2026-11822.openvex.json',
    );
  });

  it('#337: emits the row when the SAME CVE is accepted on an in-scope surface', () => {
    // Proves the filter keys on the SURFACE, not on the id or the record name:
    // an identical CVE on a pypi product IS emitted.
    const npmScoped: VexFile = {
      path: '.vex/npm-CVE-2026-11822.openvex.json',
      doc: {
        revisit_by: 'wait-for-image-rebuild',
        statements: [
          {
            vulnerability: { name: 'CVE-2026-11822' },
            status: 'not_affected',
            products: NPM_PRODUCTS,
          },
        ],
      },
    };
    expect(ignoredVulns([npmScoped]).map((r) => r.id)).toEqual([
      'CVE-2026-11822',
    ]);
  });

  it('sets ignoreUntil when a suppressing record has a dated revisit_by', () => {
    const dated: VexFile = {
      path: '.vex/CVE-2026-9999.openvex.json',
      doc: {
        revisit_by: 'revisit 2026-10-01',
        statements: [
          {
            vulnerability: { name: 'CVE-2026-9999' },
            status: 'not_affected',
            products: NPM_PRODUCTS,
          },
        ],
      },
    };
    const rows = ignoredVulns([dated]);
    expect(rows).toHaveLength(1);
    expect(rows[0].ignoreUntil).toEqual(new Date('2026-10-01T00:00:00Z'));
  });

  it('accepts a string-form vulnerability (not just {name})', () => {
    const rows = ignoredVulns([
      {
        path: '.vex/s.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: 'CVE-2026-5',
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
          ],
        },
      },
    ]);
    expect(rows.map((r) => r.id)).toEqual(['CVE-2026-5']);
  });

  it('tolerates a suppressing statement with a null/absent vulnerability (optional-chaining)', () => {
    // A not_affected statement whose `vulnerability` is null must be SKIPPED,
    // not throw — this pins the `?.name` optional chaining (a `.name` mutant
    // would throw on the null vulnerability).
    const rows = ignoredVulns([
      {
        path: '.vex/nullvuln.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: null as unknown as string,
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
            {
              vulnerability: { name: 'CVE-2026-6' },
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
          ],
        },
      },
    ]);
    expect(rows.map((r) => r.id)).toEqual(['CVE-2026-6']);
  });

  it('OMITS ignoreUntil when the record has a non-dated revisit_by', () => {
    // Pins that `ignoreUntil` is genuinely absent (not present-with-undefined):
    // the row must have NO `ignoreUntil` own-property. Kills the mutant that
    // would still set the key.
    const rows = ignoredVulns([
      {
        path: '.vex/nodate.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: { name: 'CVE-2026-7' },
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
          ],
        },
      },
    ]);
    expect(rows).toHaveLength(1);
    expect(Object.prototype.hasOwnProperty.call(rows[0], 'ignoreUntil')).toBe(
      false,
    );
  });

  it('skips a suppressing statement whose vulnerability name has no CVE token', () => {
    const rows = ignoredVulns([
      {
        path: '.vex/x.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            {
              vulnerability: { name: 'GHSA-only' },
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
          ],
        },
      },
    ]);
    expect(rows).toEqual([]);
  });

  it('skips a null statement element and non-suppressing statements within a record', () => {
    const rows = ignoredVulns([
      {
        path: '.vex/mixed.json',
        doc: {
          revisit_by: 'wait-for-image-rebuild',
          statements: [
            null as unknown as { status: string },
            {
              vulnerability: { name: 'CVE-2026-8' },
              status: 'affected',
              products: NPM_PRODUCTS,
            },
            {
              vulnerability: { name: 'CVE-2026-9' },
              status: 'not_affected',
              products: NPM_PRODUCTS,
            },
          ],
        },
      },
    ]);
    expect(rows.map((r) => r.id)).toEqual(['CVE-2026-9']);
  });
});

describe('renderTrivyYaml', () => {
  it('emits the header + every suppressing record path as a vulnerability.vex item', () => {
    const yaml = renderTrivyYaml([AFFECTED_MCP, NA_IMAGE, NA_FS]);
    expect(yaml).toContain('# GENERATED FILE');
    expect(yaml).toContain('scan:');
    expect(yaml).toContain('  skip-dirs:');
    expect(yaml).toContain('    - node_modules');
    expect(yaml).toContain('    - cdk.out');
    expect(yaml).toContain('vulnerability:');
    expect(yaml).toContain('  vex:');
    expect(yaml).toContain('    - .vex/CVE-2026-11822.openvex.json');
    expect(yaml).toContain('    - .vex/ecdsa-CVE-2024-23342.openvex.json');
    // affected mcp record is NOT listed.
    expect(yaml).not.toContain('mcp-CVE-2026-52869');
    // trailing newline (POSIX text file).
    expect(yaml.endsWith('\n')).toBe(true);
  });

  it('is deterministic and stable across input orderings', () => {
    const a = renderTrivyYaml([NA_IMAGE, NA_FS]);
    const b = renderTrivyYaml([NA_FS, NA_IMAGE]);
    expect(a).toBe(b);
  });
});

describe('renderOsvToml', () => {
  it('emits the header + an [[IgnoredVulns]] block per IN-SCOPE suppressing record', () => {
    const toml = renderOsvToml([AFFECTED_MCP, NA_IMAGE, NA_FS]);
    expect(toml).toContain('# GENERATED FILE');
    expect(toml).toContain('[[IgnoredVulns]]');
    expect(toml).toContain('id = "CVE-2024-23342"');
    // affected mcp CVE is NOT ignored (#188)…
    expect(toml).not.toContain('CVE-2026-52869');
    // …and neither is the image-scoped deb record (#337).
    expect(toml).not.toContain('CVE-2026-11822');
    expect(toml.endsWith('\n')).toBe(true);
  });

  it('documents the #337 surface scoping in the generated banner', () => {
    // The banner is the only place a human reading osv-scanner.toml learns WHY
    // an accepted image CVE has no row here — pin it so a future edit to the
    // header cannot silently drop the explanation.
    const toml = renderOsvToml([NA_FS]);
    expect(toml).toContain('ALSO omitted (#337)');
    expect(toml).toContain('# Emitted purl types: npm, pypi.');
  });

  it('escapes reason strings (quotes/newlines) safely via the TOML serializer', () => {
    const tricky: VexFile = {
      path: '.vex/CVE-2026-7777.openvex.json',
      doc: {
        revisit_by: 'wait-for-image-rebuild',
        statements: [
          {
            vulnerability: { name: 'CVE-2026-7777' },
            status: 'not_affected',
            justification: 'j',
            impact_statement: 'has "quotes" and\nnewline',
            products: NPM_PRODUCTS,
          },
        ],
      },
    };
    const toml = renderOsvToml([tricky]);
    expect(toml).toContain('id = "CVE-2026-7777"');
    expect(toml).toContain('\\"quotes\\"');
  });

  it('emits only the header when there are no suppressing records', () => {
    const toml = renderOsvToml([AFFECTED_MCP]);
    expect(toml).toContain('# GENERATED FILE');
    expect(toml).not.toContain('[[IgnoredVulns]]');
    expect(toml.endsWith('\n')).toBe(true);
  });
});

// A single `fixed` record used for byte-exact golden assertions below. Golden
// tests pin the ENTIRE rendered file (header banner + structure), which kills
// the StringLiteral mutants Stryker would otherwise leave surviving in the
// banner/scan-policy literals (the #165 bar for these security modules is 0
// surviving mutants — a corrupted generated file silently desyncs a scanner's
// suppression set from the .vex/ ledger).
//
// Its `revisit_by` is the class-C `standing-acceptance` form (#352) on purpose:
// a standing acceptance names no end event, so it must render with NO expiry in
// either dialect. Because the goldens below pin the ENTIRE file byte-for-byte,
// they are also the strongest available proof of that — an `ignoreUntil` line
// leaking in from a future change to `ignoreUntilFrom` would fail them.
const GOLDEN_FILE: VexFile = {
  path: '.vex/CVE-2026-0001.openvex.json',
  doc: {
    revisit_by: 'standing-acceptance',
    statements: [
      {
        vulnerability: { name: 'CVE-2026-0001' },
        status: 'fixed',
        justification: 'j',
        products: NPM_PRODUCTS,
      },
    ],
  },
};

const GOLDEN_HEADER_TRIVY = `# GENERATED FILE — do NOT edit by hand.
#
# Trivy's VEX suppression dialect, generated from the canonical
# .vex/*.openvex.json ledger by .github/scripts/vex-dialects.ts (#251).
# Add/remove an acceptance by editing a .vex/*.openvex.json record,
# then regenerate: \`node .github/scripts/vex-dialects.mjs write\`.
# CI (security.yml) fails if this file drifts from the generator.
# Only not_affected/fixed records suppress; affected records (e.g.
# the mcp CVEs, #226/#227) are omitted so they stay visible. See
# .vex/README.md — the single authoring surface.`;

// The OSV banner is the trivy one plus the #337 surface-scoping note — spelled
// out literally (not derived from OSV_SCANNED_PURL_TYPES) so the golden pins the
// rendered text independently of the constant that feeds it.
const GOLDEN_HEADER_OSV = `${GOLDEN_HEADER_TRIVY.replace(
  "Trivy's",
  "OSV-Scanner's",
)}
#
# ALSO omitted (#337): a record whose product purl names a surface OSV does
# not scan here (e.g. the pkg:deb/... MiniStack IMAGE records). OSV has no
# package field on an ignore entry, so such a row could never suppress the
# finding it was written for — only a same-CVE finding on the repo TREE.
# Emitted purl types: npm, pypi.`;

describe('golden output (byte-exact — pins every literal)', () => {
  it('renderTrivyYaml matches the golden file exactly', () => {
    expect(renderTrivyYaml([GOLDEN_FILE])).toBe(
      `${GOLDEN_HEADER_TRIVY}

scan:
  skip-dirs:
    - node_modules
    - cdk.out

vulnerability:
  vex:
    - .vex/CVE-2026-0001.openvex.json
`,
    );
  });

  it('renderOsvToml matches the golden file exactly (with an IgnoredVulns block)', () => {
    expect(renderOsvToml([GOLDEN_FILE])).toBe(
      `${GOLDEN_HEADER_OSV}

[[IgnoredVulns]]
id = "CVE-2026-0001"
reason = "VEX fixed (j)"
`,
    );
  });

  it('renderOsvToml matches the golden EMPTY file exactly (header only)', () => {
    expect(renderOsvToml([])).toBe(`${GOLDEN_HEADER_OSV}\n`);
  });

  it('emits an ignoreUntil datetime line when a dated revisit_by is present', () => {
    const dated: VexFile = {
      path: '.vex/CVE-2026-0002.openvex.json',
      doc: {
        revisit_by: 'revisit 2026-10-01',
        statements: [
          {
            vulnerability: { name: 'CVE-2026-0002' },
            status: 'fixed',
            justification: 'j',
            products: NPM_PRODUCTS,
          },
        ],
      },
    };
    const toml = renderOsvToml([dated]);
    // The exact IgnoredVulns block, including the serialized UTC datetime — this
    // pins that `ignoreUntil` is actually written (kills the `if (ignoreUntil)`
    // ConditionalExpression mutant that would drop the assignment).
    expect(toml).toContain(
      'id = "CVE-2026-0002"\nreason = "VEX fixed (j)"\nignoreUntil = 2026-10-01T00:00:00.000Z',
    );
  });

  it('suppresses normally in BOTH dialects for a class-C standing-acceptance, with no expiry', () => {
    // The behavioural claim the new #352 dialect form makes: `standing-acceptance`
    // is a REVISIT trigger, not a suppression modifier. It must therefore behave
    // in the dialects exactly like any other non-dated form — the record still
    // reaches trivy's file list and OSV's ignore list, and OSV gets no
    // self-expiring `ignoreUntil` (there is no end event to expire towards, so an
    // invented date would either silently re-open the finding or lie about a
    // review that was never scheduled).
    expect(renderTrivyYaml([GOLDEN_FILE])).toContain(
      '    - .vex/CVE-2026-0001.openvex.json',
    );
    const toml = renderOsvToml([GOLDEN_FILE]);
    expect(toml).toContain('id = "CVE-2026-0001"');
    expect(toml).not.toContain('ignoreUntil');
    expect(ignoreUntilFrom(GOLDEN_FILE.doc.revisit_by)).toBeUndefined();
  });
});
