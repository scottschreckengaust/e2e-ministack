// Plain-Jest *regression* replay of the npm-audit-to-sarif fuzz corpus (#295).
//
// Replays the committed seed corpus (`fuzz/corpus-npm-audit-to-sarif/`) through
// the `npm audit --json` → SARIF converter. A SARIF producer's output MUST be a
// well-formed, uploadable SARIF 2.1.0 document regardless of input, or the
// Security-tab upload step fails the job — so this must never throw and always
// return a schema-shaped doc.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import { toSarif, ghsaCveMap } from '../.github/scripts/npm-audit-to-sarif';

const CORPUS_DIR = path.join(__dirname, 'corpus-npm-audit-to-sarif');

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

const VEX_DOCS = [
  {
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-13149',
          aliases: ['GHSA-3jxr-9vmj-r5cp'],
        },
        status: 'affected',
      },
    ],
  },
];

// A well-formed SARIF 2.1.0 doc: version + $schema strings, one run, results an
// array whose entries carry a string ruleId, a valid level, and a location.
function assertWellFormedSarif(sarif: unknown): void {
  const s = sarif as {
    version?: unknown;
    $schema?: unknown;
    runs?: Array<{ results?: unknown[] }>;
  };
  expect(s.version).toBe('2.1.0');
  expect(typeof s.$schema).toBe('string');
  expect(Array.isArray(s.runs)).toBe(true);
  const results = s.runs?.[0]?.results;
  expect(Array.isArray(results)).toBe(true);
  for (const r of results as Array<Record<string, unknown>>) {
    expect(typeof r.ruleId).toBe('string');
    expect((r.ruleId as string).length).toBeGreaterThan(0);
    expect(['error', 'warning', 'note']).toContain(r.level);
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('npm-audit-to-sarif — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('produces a valid empty-results SARIF on degenerate inputs', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      const sarif = toSarif(v, VEX_DOCS);
      assertWellFormedSarif(sarif);
      expect(sarif.runs[0].results).toEqual([]);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s into a well-formed SARIF',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      assertWellFormedSarif(toSarif(parsed, VEX_DOCS));
      // also tolerate missing/garbage vex docs
      assertWellFormedSarif(toSarif(parsed, undefined as unknown as unknown[]));
    },
  );

  it('never throws on adversarial audit / vex inputs', () => {
    for (const v of [
      { vulnerabilities: { x: 42 } },
      { vulnerabilities: { x: { severity: 7, via: 'nope' } } },
      { vulnerabilities: { x: { via: [{ url: ['GHSA-aaaa-bbbb-cccc'] }] } } },
    ]) {
      expect(() => assertWellFormedSarif(toSarif(v, VEX_DOCS))).not.toThrow();
    }
    for (const v of [
      undefined,
      null,
      'x',
      [{ statements: 'no' }],
      [{ statements: [42] }],
    ]) {
      expect(() => ghsaCveMap(v as unknown as unknown[])).not.toThrow();
    }
  });

  it('builds a synthetic audit doc from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('brace-expansion GHSA-3jxr-9vmj-r5cp high'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6]),
      Buffer.from('q'.repeat(200)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const doc = {
        vulnerabilities: {
          [fdp.consumeString(10) || 'pkg']: {
            severity: fdp.consumeString(8),
            via: [{ url: `advisories/${fdp.consumeString(20)}` }],
          },
        },
      };
      expect(() => assertWellFormedSarif(toSarif(doc, VEX_DOCS))).not.toThrow();
    }
  });
});
