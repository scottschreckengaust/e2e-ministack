// Plain-Jest *regression* replay of the npm-audit-gate fuzz corpus (#295).
//
// Replays the committed seed corpus (`fuzz/corpus-npm-audit-gate/`) through the
// VEX-aware npm-audit gate decider. This module decides whether the `npm audit`
// gate reds, so it must never throw on a malformed/partial `npm audit --json`
// and must always return a well-formed, sorted, deduped list of uncovered
// package names.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  uncoveredAdvisories,
  coveredAdvisories,
  advisoryGhsaIds,
  gateResult,
} from '../.github/scripts/npm-audit-gate';

const CORPUS_DIR = path.join(__dirname, 'corpus-npm-audit-gate');

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

// The brace-expansion acceptance (CVE name + GHSA alias) so the replay exercises
// the GHSA-keyed coverage path.
const ACCEPTED = new Set(['CVE-2026-13149', 'GHSA-3JXR-9VMJ-R5CP']);
const NOW = new Date('2026-07-22T12:00:00.000Z');

function assertWellFormed(ids: string[]): void {
  expect(Array.isArray(ids)).toBe(true);
  for (const id of ids) {
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
  }
  expect(ids).toEqual([...ids].sort());
  expect(new Set(ids).size).toBe(ids.length);
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('npm-audit-gate — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('returns an empty (passing) list on empty/degenerate inputs', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      expect(uncoveredAdvisories(v, ACCEPTED)).toEqual([]);
      expect(coveredAdvisories(v, ACCEPTED)).toEqual([]);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the invariants',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      assertWellFormed(uncoveredAdvisories(parsed, ACCEPTED));
      // An empty accepted set is fail-closed: never fewer uncovered than with
      // the acceptance set (an accepted id can only REMOVE entries).
      const withEmpty = uncoveredAdvisories(parsed, new Set());
      assertWellFormed(withEmpty);
      expect(withEmpty.length).toBeGreaterThanOrEqual(
        uncoveredAdvisories(parsed, ACCEPTED).length,
      );
      // gateResult is always a well-formed struct with a valid outcome.
      const r = gateResult(parsed, [], NOW);
      expect(['success', 'failure']).toContain(r.outcome);
      expect(typeof r.acceptedCount).toBe('number');
    },
  );

  it('never throws on adversarial parsed values', () => {
    for (const v of [
      { vulnerabilities: 42 },
      { vulnerabilities: { x: 7 } },
      { vulnerabilities: { x: { via: 'nope' } } },
      { vulnerabilities: { x: { via: [null, 3, { url: 42 }] } } },
      'not-an-object',
      [1, 2, 3],
    ]) {
      expect(() => uncoveredAdvisories(v, ACCEPTED)).not.toThrow();
      expect(() => coveredAdvisories(v, ACCEPTED)).not.toThrow();
      expect(() => gateResult(v, [], NOW)).not.toThrow();
    }
  });

  it('builds a synthetic audit doc from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('brace-expansion GHSA-3jxr-9vmj-r5cp'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6]),
      Buffer.from('z'.repeat(200)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const doc = {
        vulnerabilities: {
          [fdp.consumeString(10) || 'pkg']: {
            severity: fdp.consumeString(8),
            via: [
              { url: `advisories/${fdp.consumeString(20)}` },
              fdp.consumeString(6),
            ],
          },
        },
      };
      expect(() => {
        assertWellFormed(uncoveredAdvisories(doc, ACCEPTED));
        advisoryGhsaIds(doc.vulnerabilities);
      }).not.toThrow();
    }
  });
});
