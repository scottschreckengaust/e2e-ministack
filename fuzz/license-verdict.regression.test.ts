// Plain-Jest *regression* replay of the license-verdict fuzz corpus (#165).
//
// Replays the committed seed corpus (`fuzz/corpus-license/`) through the SPDX
// allow-list satisfiability decider, asserting its invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`) and emits into
// `reports/junit/fuzz.xml`. `license-verdict` makes ACCEPT/REJECT decisions
// that close or escalate `license-review` issues, so its robustness is
// security-relevant: it must never throw for a non-empty allow-list, and must
// always return a boolean (the conservative fallback → `false` on anything
// unparseable/malformed).
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import { isAcceptable } from '../.github/scripts/license-verdict';

const CORPUS_DIR = path.join(__dirname, 'corpus-license');
const ALLOW = 'MIT, Apache-2.0, ISC, BSD-2-Clause, BSD-3-Clause, 0BSD';

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

/** The decider invariants: returns a boolean; never throws for a valid
 * (non-empty) allow-list. */
function assertInvariants(expr: string, allow = ALLOW): void {
  const verdict = isAcceptable(expr, allow);
  expect(typeof verdict).toBe('boolean');
}

describe('license-verdict — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('rejects empty / marker expressions (conservative fallback)', () => {
    expect(isAcceptable('', ALLOW)).toBe(false);
    expect(isAcceptable('NONE', ALLOW)).toBe(false);
    expect(isAcceptable('NOASSERTION', ALLOW)).toBe(false);
  });

  it.each(corpusFiles)(
    'replays corpus expression %s without violating the decider invariants',
    (file) => {
      const expr = fs
        .readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file)))
        .toString('utf8');
      assertInvariants(expr);
      // Also feed it through a FuzzedDataProvider-derived allow-list to exercise
      // the allow-list parsing path (still a valid, non-empty list).
      const fdp = new FuzzedDataProvider(
        expr.length ? Buffer.from(expr) : Buffer.from([1]),
      );
      const synthAllow = `${fdp.consumeString(16)},MIT`;
      expect(typeof isAcceptable(expr, synthAllow)).toBe('boolean');
    },
  );

  it('never throws on adversarial / binary / very-long expressions', () => {
    const nasties = [
      '\0\0\0',
      '(((((((((((',
      ')))))))))))',
      'MIT '.repeat(50000),
      'A'.repeat(100000),
      String.fromCharCode(0, 255, 40, 41),
      'MIT WITH WITH WITH',
      '(MIT OR (Apache-2.0 AND (ISC OR (0BSD))))',
    ];
    for (const n of nasties) {
      expect(() => isAcceptable(n, ALLOW)).not.toThrow();
      expect(typeof isAcceptable(n, ALLOW)).toBe('boolean');
    }
  });

  it('throws ONLY on an empty allow-list (the documented usage error)', () => {
    expect(() => isAcceptable('MIT', '')).toThrow(/empty allow-list/);
    expect(() => isAcceptable('MIT', '  , ,')).toThrow(/empty allow-list/);
  });
});
