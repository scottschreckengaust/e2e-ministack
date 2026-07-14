// Plain-Jest *regression* replay of the vex-report fuzz corpus (#189).
//
// Replays the committed seed corpus (`fuzz/corpus-vex-report/`) through the
// VEX-report builder + renderer, asserting its invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`) and emits into
// `reports/junit/fuzz.xml`, so a crash input pinned into the corpus becomes a
// permanent regression test. The report is what a reviewer reads to decide
// whether accepted risk needs re-examination, so its robustness is
// security-relevant: it must never throw and must always render a well-formed
// markdown document (summary + action block + collapsed <details> ledger).
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  buildReport,
  renderMarkdown,
  summarize,
  type VexRecord,
  type ScannerFinding,
} from '../.github/scripts/vex-report';

const CORPUS_DIR = path.join(__dirname, 'corpus-vex-report');

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
 * The report invariants: never throws; always a well-formed markdown report.
 * `buildReport` takes arrays by contract (the CLI shim guarantees that), so the
 * harness coerces non-arrays to `[]` exactly as the shim does — the fuzz target
 * is ELEMENT-level robustness (junk rows inside the arrays), which buildReport
 * owns; array-ness is the shim's boundary and is asserted in the unit tier.
 */
function assertInvariants(
  vex: unknown,
  findings: unknown,
  today: unknown,
): void {
  const rows = buildReport(
    (Array.isArray(vex) ? vex : []) as VexRecord[],
    (Array.isArray(findings) ? findings : []) as ScannerFinding[],
    'HIGH',
    typeof today === 'string' ? today : '',
  );
  expect(Array.isArray(rows)).toBe(true);
  const md = renderMarkdown(rows);
  expect(typeof md).toBe('string');
  expect(md).toContain('**VEX report** —');
  expect(md).toContain('<details>'); // collapsed ledger always present
  expect(md).not.toContain('<details open'); // never auto-expanded
  const s = summarize(rows);
  // Every row has a defined status counted exactly once.
  const total = Object.values(s).reduce((a, b) => a + b, 0);
  expect(total).toBe(rows.length);
  for (const r of rows) {
    expect(typeof r.item).toBe('string');
    expect(typeof r.status).toBe('string');
    expect(typeof r.actionNeeded).toBe('boolean');
    expect(Array.isArray(r.tools)).toBe(true);
    expect(Array.isArray(r.packages)).toBe(true);
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('vex-report — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('renders empty/degenerate inputs to a valid report', () => {
    for (const vex of [undefined, null, [], [{}], 'x']) {
      for (const f of [undefined, null, [], 'x']) {
        assertInvariants(vex, f, '2026-07-14');
      }
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the report invariants',
    (file) => {
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      const parsed = tryParse(data);
      // A corpus buffer may be a {vex, findings, today} bag, or a bare array.
      const bag = (parsed ?? {}) as {
        vex?: unknown;
        findings?: unknown;
        today?: unknown;
      };
      assertInvariants(bag.vex, bag.findings, bag.today);
      // Also feed the whole parsed value as each arg to stress type-tolerance.
      assertInvariants(parsed, parsed, parsed);
    },
  );

  it('builds a synthetic report from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('CVE-2026-1 not_affected HIGH'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8]),
      Buffer.from('x'.repeat(400)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const n = fdp.consumeIntegralInRange(1, 9999);
      const vex: VexRecord[] = [
        {
          cve: `CVE-2026-${n}`,
          status: fdp.consumeString(16),
          justification: fdp.consumeString(20),
          revisitBy: fdp.consumeString(12),
        },
      ];
      const findings: ScannerFinding[] = [
        {
          id: `CVE-2026-${n}`,
          scanner: fdp.consumeString(8) || 'grype',
          severity: fdp.consumeString(10),
          pkg: fdp.consumeString(12),
        },
      ];
      assertInvariants(vex, findings, fdp.consumeString(10));
    }
  });

  it('never throws on adversarial parsed values', () => {
    const nasties: [unknown, unknown, unknown][] = [
      [42, 42, 42],
      ['s', 's', 's'],
      [[null, 7], [null, 7], null],
      [[{ cve: 'CVE-2026-1' }], [{ id: 'CVE-2026-1' }], 'not-a-date'],
      [[{ cve: '' }], [{ id: '', scanner: 'x', severity: 'HIGH' }], ''],
    ];
    for (const [v, f, t] of nasties) {
      expect(() => assertInvariants(v, f, t)).not.toThrow();
    }
  });
});
