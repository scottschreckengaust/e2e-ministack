// Plain-Jest *regression* replay of the alerts-findings fuzz corpus (#189 CI).
//
// Replays the committed seed corpus (`fuzz/corpus-alerts-findings/`) through
// the Code Scanning Alerts parser, asserting its invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`). The parser feeds the
// per-push VEX report, so it must never throw on a malformed/partial Alerts API
// response and must always return a well-formed AlertFinding[] (every row has
// string id/scanner/badgeSeverity/state/dismissedReason/category, id non-empty).
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  parseAlerts,
  filterByCategory,
  toScannerFindings,
  type AlertFinding,
} from '../.github/scripts/alerts-findings';

const CORPUS_DIR = path.join(__dirname, 'corpus-alerts-findings');

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

function assertWellFormed(findings: readonly AlertFinding[]): void {
  expect(Array.isArray(findings)).toBe(true);
  for (const f of findings) {
    expect(typeof f.id).toBe('string');
    expect(f.id).not.toBe('');
    expect(typeof f.scanner).toBe('string');
    expect(typeof f.badgeSeverity).toBe('string');
    expect(typeof f.state).toBe('string');
    expect(typeof f.dismissedReason).toBe('string');
    expect(typeof f.category).toBe('string');
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('alerts-findings — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('parses empty/degenerate inputs to []', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      expect(parseAlerts(v)).toEqual([]);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the invariants',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      const f = parseAlerts(parsed);
      assertWellFormed(f);
      // Filtering by arbitrary categories must also stay well-formed.
      assertWellFormed(filterByCategory(f, ['grype-ministack-image']));
      assertWellFormed(filterByCategory(f, []));
      // The report-shape adapter must map every finding totally: same length,
      // badgeSeverity carried into `severity`, id/scanner preserved.
      const sf = toScannerFindings(f);
      expect(sf).toHaveLength(f.length);
      for (let i = 0; i < f.length; i++) {
        expect(sf[i].severity).toBe(f[i].badgeSeverity);
        expect(sf[i].id).toBe(f[i].id);
        expect(sf[i].scanner).toBe(f[i].scanner);
      }
    },
  );

  it('builds a synthetic alerts array from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('CVE-2026-1 high dismissed'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8]),
      Buffer.from('x'.repeat(300)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const n = fdp.consumeIntegralInRange(1, 9999);
      const alerts = [
        {
          state: fdp.consumeString(10),
          dismissed_reason: fdp.consumeString(12),
          rule: {
            id: `CVE-2026-${n}-${fdp.consumeString(6)}`,
            security_severity_level: fdp.consumeString(8),
          },
          tool: { name: fdp.consumeString(8) },
          most_recent_instance: { category: fdp.consumeString(12) },
        },
      ];
      assertWellFormed(parseAlerts(alerts));
    }
  });

  it('never throws on adversarial parsed values', () => {
    for (const v of [
      [{ rule: 42, tool: 'x', most_recent_instance: [] }],
      [{ rule: { id: ['CVE'] } }],
      [{ state: 99, rule: { id: 'CVE-2026-1' } }],
      [{ rule: { id: 'CVE-2026-1', security_severity_level: {} } }],
      'not-an-array',
    ]) {
      expect(() => parseAlerts(v)).not.toThrow();
    }
  });
});
