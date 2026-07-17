import {
  SUPPRESSING_STATUSES,
  suppressingRecords,
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

// A not_affected image-CVE record, shaped like .vex/CVE-*.openvex.json.
const NA_IMAGE: VexFile = {
  path: '.vex/CVE-2026-11822.openvex.json',
  doc: {
    statements: [
      {
        vulnerability: { name: 'CVE-2026-11822' },
        status: 'not_affected',
        justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
        impact_statement: 'Accepted risk: local-only CI emulator.',
      },
    ],
  },
};

// A not_affected FS-surface record (ecdsa-style, pypi purl).
const NA_FS: VexFile = {
  path: '.vex/ecdsa-CVE-2024-23342.openvex.json',
  doc: {
    statements: [
      {
        vulnerability: { name: 'CVE-2024-23342' },
        status: 'not_affected',
        justification: 'vulnerable_code_not_in_execute_path',
        impact_statement: 'Signing path unreachable.',
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
      { vulnerability: { name: 'CVE-2026-52869' }, status: 'affected' },
    ],
  },
};

// A `fixed` record.
const FIXED: VexFile = {
  path: '.vex/CVE-2026-0001.openvex.json',
  doc: {
    statements: [{ vulnerability: { name: 'CVE-2026-0001' }, status: 'fixed' }],
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
        doc: { statements: [{ vulnerability: { name: 'CVE-2026-3' } }] },
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
    expect(ignoreUntilFrom(undefined)).toBeUndefined();
    expect(ignoreUntilFrom(42 as unknown as string)).toBeUndefined();
    expect(ignoreUntilFrom('')).toBeUndefined();
  });
});

describe('ignoredVulns (OSV [[IgnoredVulns]] rows)', () => {
  it('maps each suppressing record to an {id, reason} row, sorted by path', () => {
    const rows = ignoredVulns([AFFECTED_MCP, NA_IMAGE, NA_FS]);
    expect(rows.map((r) => r.id)).toEqual(['CVE-2026-11822', 'CVE-2024-23342']);
    expect(rows[0].reason).toContain('not_affected');
    expect(rows[0].ignoreUntil).toBeUndefined();
  });

  it('sets ignoreUntil when a suppressing record has a dated revisit_by', () => {
    const dated: VexFile = {
      path: '.vex/CVE-2026-9999.openvex.json',
      doc: {
        revisit_by: 'revisit 2026-10-01',
        statements: [
          { vulnerability: { name: 'CVE-2026-9999' }, status: 'not_affected' },
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
          statements: [{ vulnerability: 'CVE-2026-5', status: 'not_affected' }],
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
          statements: [
            {
              vulnerability: null as unknown as string,
              status: 'not_affected',
            },
            { vulnerability: { name: 'CVE-2026-6' }, status: 'not_affected' },
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
            { vulnerability: { name: 'CVE-2026-7' }, status: 'not_affected' },
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
          statements: [
            { vulnerability: { name: 'GHSA-only' }, status: 'not_affected' },
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
          statements: [
            null as unknown as { status: string },
            { vulnerability: { name: 'CVE-2026-8' }, status: 'affected' },
            { vulnerability: { name: 'CVE-2026-9' }, status: 'not_affected' },
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
  it('emits the header + an [[IgnoredVulns]] block per suppressing record', () => {
    const toml = renderOsvToml([AFFECTED_MCP, NA_IMAGE, NA_FS]);
    expect(toml).toContain('# GENERATED FILE');
    expect(toml).toContain('[[IgnoredVulns]]');
    expect(toml).toContain('id = "CVE-2026-11822"');
    expect(toml).toContain('id = "CVE-2024-23342"');
    // affected mcp CVE is NOT ignored.
    expect(toml).not.toContain('CVE-2026-52869');
    expect(toml.endsWith('\n')).toBe(true);
  });

  it('escapes reason strings (quotes/newlines) safely via the TOML serializer', () => {
    const tricky: VexFile = {
      path: '.vex/CVE-2026-7777.openvex.json',
      doc: {
        statements: [
          {
            vulnerability: { name: 'CVE-2026-7777' },
            status: 'not_affected',
            justification: 'j',
            impact_statement: 'has "quotes" and\nnewline',
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
const GOLDEN_FILE: VexFile = {
  path: '.vex/CVE-2026-0001.openvex.json',
  doc: {
    statements: [
      {
        vulnerability: { name: 'CVE-2026-0001' },
        status: 'fixed',
        justification: 'j',
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

const GOLDEN_HEADER_OSV = GOLDEN_HEADER_TRIVY.replace(
  "Trivy's",
  "OSV-Scanner's",
);

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
});
