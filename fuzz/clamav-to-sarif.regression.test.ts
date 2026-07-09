// Plain-Jest *regression* replay of the clamav-to-sarif fuzz corpus (#165).
//
// The sibling of the (future) exploratory jazzer target: this REPLAYS the
// committed seed corpus (`fuzz/corpus-clamav/`) through the SARIF parser as
// ordinary Jest tests, asserting the parser's invariants. It runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`,
// `npm run test:fuzz-regression`) and emits into `reports/junit/fuzz.xml`, so a
// crash input pinned into the corpus becomes a permanent regression test.
//
// It uses jazzer's `FuzzedDataProvider` (imported from the addon-free
// `@jazzer.js/core/dist/` path, like handler.regression.test.js) to derive a
// scan-log string from each corpus buffer, then feeds it to `toSarif`. The
// parser's output GATES the ClamAV Code-Scanning alert stream, so its
// robustness is security-relevant: it must never throw, and must always emit a
// well-formed empty-or-more-results SARIF 2.1.0 document.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import { toSarif } from '../.github/scripts/clamav-to-sarif';

const CORPUS_DIR = path.join(__dirname, 'corpus-clamav');

/**
 * Confine a corpus filename to CORPUS_DIR before it is joined onto a filesystem
 * path — the same containment guard as handler.regression.test.js. Any value
 * that is not a single, plain path segment is rejected outright (separators
 * under both OS conventions, `.`/`..`, NUL byte, and `:`).
 */
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
 * Derive a scan-log string from corpus bytes. Two shapes: interpret the buffer
 * DIRECTLY as UTF-8 log text (how a real clamdscan log arrives), or build a
 * synthetic `PATH: SIG FOUND` line from fuzzed fields — mirroring the byte
 * consumption a standalone jazzer target would use.
 */
function decodeLogText(data: Buffer): string {
  if (data.length === 0) return '';
  const fdp = new FuzzedDataProvider(data);
  const mode = fdp.consumeIntegralInRange(0, 1);
  if (mode === 0) {
    // Whole buffer as log text.
    return data.toString('utf8');
  }
  // Synthetic finding line assembled from fuzzed path + signature.
  const p = fdp.consumeString(64);
  const sig = fdp.consumeString(32);
  return `${p}: ${sig} FOUND\n`;
}

/** The parser invariants: never throws; always a well-formed SARIF 2.1.0 doc. */
function assertInvariants(logText: string): void {
  const sarif = toSarif(logText);
  expect(sarif.version).toBe('2.1.0');
  expect(typeof sarif.$schema).toBe('string');
  expect(Array.isArray(sarif.runs)).toBe(true);
  expect(sarif.runs[0].tool.driver.name).toBe('ClamAV');
  expect(Array.isArray(sarif.runs[0].results)).toBe(true);
  for (const r of sarif.runs[0].results) {
    // Every emitted result is a valid, critical finding with a location.
    expect(typeof r.ruleId).toBe('string');
    expect(r.ruleId).not.toBe('');
    expect(r.level).toBe('error');
    expect(r.properties['security-severity']).toBe('10.0');
    expect(typeof r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'string',
    );
  }
}

describe('clamav-to-sarif — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('parses the empty input into a valid empty-results SARIF', () => {
    assertInvariants('');
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the parser invariants',
    (file) => {
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      // Both decode shapes must hold the invariants.
      assertInvariants(data.toString('utf8'));
      assertInvariants(decodeLogText(data));
    },
  );

  it('never throws on adversarial/binary/very-long inputs', () => {
    const nasties = [
      '\0\0\0',
      ': FOUND',
      'x'.repeat(100000) + ': Sig FOUND',
      'a: b: c: d FOUND',
      '----------- SCAN SUMMARY -----------\nx: y FOUND',
      Buffer.from([0, 255, 128, 10, 58, 32]).toString('utf8'),
    ];
    for (const n of nasties) {
      expect(() => toSarif(n)).not.toThrow();
    }
  });
});
