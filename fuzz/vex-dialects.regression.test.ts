// Plain-Jest *regression* replay of the vex-dialects fuzz corpus (issue #251).
//
// Replays the committed seed corpus (`fuzz/corpus-vex-dialects/`) through the
// scanner-dialect generator, asserting its invariants. Runs in the PR-gating
// fuzz-regression tier (`jest.fuzz.config.js`) and emits into
// `reports/junit/fuzz.xml`, so a crash input pinned into the corpus becomes a
// permanent regression test. Each corpus buffer is candidate JSON — an OpenVEX
// doc (or a degenerate value) — wrapped as a `{ path, doc }` VexFile exactly as
// the `vex-dialects.mjs` CLI builds them from `.vex/`.
//
// The generator's output GATES two scanners' suppression sets (trivy.yaml,
// osv-scanner.toml), so it must never throw and must always produce a stable,
// well-formed dialect. The load-bearing invariant: only not_affected/fixed
// records suppress; `affected` NEVER emits a suppression in any dialect.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  suppressingRecords,
  ignoredVulns,
  renderTrivyYaml,
  renderOsvToml,
  type VexFile,
} from '../.github/scripts/vex-dialects';

const CORPUS_DIR = path.join(__dirname, 'corpus-vex-dialects');

function sanitizeCorpusName(name: string): string {
  if (
    typeof name !== 'string' ||
    name === '' ||
    name === '.' ||
    name === '..' ||
    name.includes('\0') ||
    name.includes(':') ||
    path.win32.basename(name) !== name ||
    path.posix.basename(name) !== name
  ) {
    throw new Error(`unsafe corpus filename (path traversal): ${name}`);
  }
  return name;
}

const corpusFiles = fs
  .readdirSync(CORPUS_DIR)
  .filter((entry) =>
    fs.statSync(path.join(CORPUS_DIR, sanitizeCorpusName(entry))).isFile(),
  )
  .sort();

/**
 * The generator invariants: never throws; both renderers return a string that
 * ends with a newline; `affected` records never appear in either dialect; every
 * OSV row carries a CVE id + string reason; and output is deterministic (a
 * second render of the same input is byte-identical).
 */
function assertInvariants(files: unknown): void {
  const list = files as VexFile[];
  const kept = suppressingRecords(list);
  expect(Array.isArray(kept)).toBe(true);
  const rows = ignoredVulns(list);
  expect(Array.isArray(rows)).toBe(true);
  for (const r of rows) {
    expect(typeof r.id).toBe('string');
    expect(r.id).toMatch(/^CVE-\d{4}-\d+$/);
    expect(typeof r.reason).toBe('string');
  }
  const trivy = renderTrivyYaml(list);
  const osv = renderOsvToml(list);
  expect(typeof trivy).toBe('string');
  expect(typeof osv).toBe('string');
  expect(trivy.endsWith('\n')).toBe(true);
  expect(osv.endsWith('\n')).toBe(true);
  // No affected record leaks into either dialect: a record kept by
  // suppressingRecords must NOT be one whose only statement is affected.
  for (const rec of kept) {
    const statuses = (rec.doc.statements ?? []).map((s) => s && s.status);
    expect(statuses.some((s) => s === 'not_affected' || s === 'fixed')).toBe(
      true,
    );
  }
  // Deterministic.
  expect(renderTrivyYaml(list)).toBe(trivy);
  expect(renderOsvToml(list)).toBe(osv);
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('vex-dialects — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('maps empty/degenerate inputs to valid, stable dialects', () => {
    for (const files of [
      undefined,
      null,
      [],
      [null],
      [{}],
      [{ path: '.vex/x.json', doc: {} }],
      [{ path: '.vex/x.json', doc: { statements: 'nope' } }],
      'not-an-array',
      42,
    ]) {
      expect(() => assertInvariants(files)).not.toThrow();
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the generator invariants',
    (file) => {
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      const parsed = tryParse(data);
      // Each corpus buffer is a candidate OpenVEX doc — wrap it as a VexFile,
      // exactly as the CLI builds { path, doc } from a .vex/ file.
      const files = [{ path: `.vex/${file}.openvex.json`, doc: parsed }];
      assertInvariants(files);
      // Also feed the raw parsed value as the list itself (adversarial shape).
      assertInvariants(parsed);
    },
  );

  it('builds synthetic VexFiles from fuzzed bytes and generates safely', () => {
    for (const seed of [
      Buffer.from('CVE-2026-11822: not_affected'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
      Buffer.from('x'.repeat(500)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const cveNum = fdp.consumeIntegralInRange(1, 99999);
      const status = fdp.consumeString(16);
      const files: VexFile[] = [
        {
          path: `.vex/CVE-2026-${cveNum}.openvex.json`,
          doc: {
            revisit_by: fdp.consumeString(24),
            statements: [
              {
                vulnerability: { name: `CVE-2026-${cveNum}` },
                status,
                justification: fdp.consumeString(16),
                impact_statement: fdp.consumeString(32),
              },
            ],
          },
        },
      ];
      assertInvariants(files);
    }
  });

  it('never throws on adversarial values', () => {
    const nasties: unknown[] = [
      42,
      'a string',
      [1, 2, 3],
      [{ path: 42, doc: null }],
      [{ path: '.vex/x.json', doc: { statements: [null, 7, {}] } }],
      [
        {
          path: '.vex/x.json',
          doc: { statements: [{ status: 'not_affected' }] },
        },
      ],
    ];
    for (const files of nasties) {
      expect(() => {
        suppressingRecords(files as VexFile[]);
        ignoredVulns(files as VexFile[]);
        renderTrivyYaml(files as VexFile[]);
        renderOsvToml(files as VexFile[]);
      }).not.toThrow();
    }
  });
});
