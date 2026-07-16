// Plain-Jest *regression* replay of the gate-findings fuzz corpus (#208).
//
// Replays the committed seed corpus (`fuzz/corpus-gate-findings/`) through the
// scanner gate-severity parsers, asserting their invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`). The parsers feed the
// VEX report's gate-vs-badge column, so they must never throw on a
// malformed/partial scanner JSON and must always return a well-formed
// CVE-id -> severity Map (every key a canonical CVE, every value a known
// severity keyword).
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  parseGrypeGate,
  parseTrivyGate,
  mergeGateSeverities,
  normGateSeverity,
} from '../.github/scripts/gate-findings';

const CORPUS_DIR = path.join(__dirname, 'corpus-gate-findings');

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

const CVE_RE = /^CVE-\d{4}-\d+$/;
const SEV = new Set([
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
  'NEGLIGIBLE',
  'UNKNOWN',
]);

// Every key is a canonical upper-case CVE, every value a known severity keyword.
function assertWellFormed(m: Map<string, string>): void {
  expect(m).toBeInstanceOf(Map);
  for (const [cve, sev] of m) {
    expect(cve).toMatch(CVE_RE);
    expect(cve).toBe(cve.toUpperCase());
    expect(SEV.has(sev)).toBe(true);
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('gate-findings — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('parses empty/degenerate inputs to an empty Map', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      expect(parseGrypeGate(v).size).toBe(0);
      expect(parseTrivyGate(v).size).toBe(0);
    }
    expect(mergeGateSeverities([]).size).toBe(0);
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the invariants',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      const g = parseGrypeGate(parsed);
      const t = parseTrivyGate(parsed);
      assertWellFormed(g);
      assertWellFormed(t);
      // Merging both (a file is one shape, so one is empty) stays well-formed
      // and never drops a key present in either input.
      const merged = mergeGateSeverities([g, t]);
      assertWellFormed(merged);
      for (const cve of [...g.keys(), ...t.keys()]) {
        expect(merged.has(cve)).toBe(true);
      }
    },
  );

  it('builds synthetic scanner JSON from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('CVE-2026-1 High'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8]),
      Buffer.from('x'.repeat(300)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const n = fdp.consumeIntegralInRange(1, 9999);
      const sev = fdp.consumeString(12);
      const grype = {
        matches: [
          {
            vulnerability: {
              id: `CVE-2026-${n}-${fdp.consumeString(6)}`,
              severity: sev,
            },
          },
          { vulnerability: 42 },
        ],
      };
      const trivy = {
        Results: [
          {
            Vulnerabilities: [
              { VulnerabilityID: `CVE-2026-${n}`, Severity: sev },
            ],
          },
          { Vulnerabilities: 'nope' },
        ],
      };
      expect(() => assertWellFormed(parseGrypeGate(grype))).not.toThrow();
      expect(() => assertWellFormed(parseTrivyGate(trivy))).not.toThrow();
      // normGateSeverity is total on any fuzzed string.
      expect(SEV.has(normGateSeverity(sev))).toBe(true);
    }
  });

  it('never throws on adversarial parsed values', () => {
    for (const v of [
      { matches: 42 },
      { matches: ['x', 7, null, { vulnerability: { id: ['CVE'] } }] },
      { Results: 42 },
      { Results: [{ Vulnerabilities: [{ VulnerabilityID: 99 }] }] },
      'not-an-object',
      [1, 2, 3],
    ]) {
      expect(() => parseGrypeGate(v)).not.toThrow();
      expect(() => parseTrivyGate(v)).not.toThrow();
    }
  });
});
