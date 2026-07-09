// Plain-Jest *regression* replay of the sonar-to-sarif fuzz corpus (#165).
//
// Replays the committed seed corpus (`fuzz/corpus-sonar/`) through the
// SonarQube-issues → SARIF parser, asserting its invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`) and emits into
// `reports/junit/fuzz.xml`, so a crash input pinned into the corpus becomes a
// permanent regression test. Each corpus buffer is treated as (candidate) JSON
// text — the exact input the `sonar-to-sarif.mjs` CLI reads — plus a
// FuzzedDataProvider-built synthetic issue, exercising both the JSON.parse
// failure path (caller's concern) and the mapping's own robustness.
//
// The parser's output GATES the SonarQube Code-Scanning alert stream, so it
// must never throw on any parsed object and must always emit a well-formed
// SARIF 2.1.0 document.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import { toSarif } from '../.github/scripts/sonar-to-sarif';

const CORPUS_DIR = path.join(__dirname, 'corpus-sonar');

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

/** The parser invariants: never throws; always a well-formed SARIF 2.1.0 doc. */
function assertInvariants(response: unknown): void {
  const sarif = toSarif(response as never);
  expect(sarif.version).toBe('2.1.0');
  expect(typeof sarif.$schema).toBe('string');
  expect(sarif.runs[0].tool.driver.name).toBe('SonarQube');
  expect(Array.isArray(sarif.runs[0].tool.driver.rules)).toBe(true);
  expect(Array.isArray(sarif.runs[0].results)).toBe(true);
  for (const r of sarif.runs[0].results) {
    expect(typeof r.ruleId).toBe('string');
    expect(['error', 'warning', 'note']).toContain(r.level);
    expect(typeof r.message.text).toBe('string');
    expect(typeof r.locations[0].physicalLocation.artifactLocation.uri).toBe(
      'string',
    );
  }
}

/** Parse corpus bytes as JSON; a parse failure is the CALLER's concern (the
 * `.mjs` shim JSON.parses before calling toSarif), so here we simply skip
 * un-parseable buffers — the mapping only ever sees an object. */
function tryParse(data: Buffer): unknown | undefined {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('sonar-to-sarif — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('maps empty/degenerate responses to a valid empty-results SARIF', () => {
    for (const r of [undefined, null, {}, { issues: [], components: [] }]) {
      assertInvariants(r);
      expect(toSarif(r as never).runs[0].results).toEqual([]);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the parser invariants',
    (file) => {
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      const parsed = tryParse(data);
      // Whatever parses (object / array / null / number / string) must map
      // without throwing to a valid SARIF doc.
      assertInvariants(parsed);
    },
  );

  it('builds a synthetic issue from fuzzed bytes and maps it safely', () => {
    // Mirror a standalone jazzer target: assemble an issue from fuzzed fields.
    for (const seed of [
      Buffer.from('the quick brown fox: FOUND'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
      Buffer.from('x'.repeat(500)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const response = {
        issues: [
          {
            rule: fdp.consumeString(16),
            severity: fdp.consumeString(8),
            component: fdp.consumeString(32),
            message: fdp.consumeString(32),
            line: fdp.consumeIntegral(4),
          },
        ],
        components: [],
      };
      assertInvariants(response);
    }
  });

  it('never throws on non-object / adversarial parsed values', () => {
    for (const v of [
      null,
      undefined,
      42,
      'a string',
      [1, 2, 3],
      { issues: 'not-an-array' },
      { issues: [{}], components: 'nope' },
      { issues: [{ component: ': leading colon' }] },
      { issues: [{ message: 'x FOUND: y' }] },
    ]) {
      expect(() => toSarif(v as never)).not.toThrow();
    }
  });
});
