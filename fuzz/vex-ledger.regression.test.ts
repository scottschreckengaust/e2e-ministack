// Plain-Jest *regression* replay of the vex-ledger fuzz corpus (#295).
//
// Replays the committed seed corpus (`fuzz/corpus-vex-ledger/`) through the
// SHARED VEX ledger core, asserting its totality invariants. This module backs
// EVERY VEX-aware gate (grype-fs, npm-audit, and the dialect generators), so it
// must never throw on a malformed/partial OpenVEX doc set and must always return
// a well-formed Set of normalized ids.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  recordIds,
  activeRecordIds,
  statementIds,
  isRevisitOverdue,
} from '../.github/scripts/vex-ledger';

const CORPUS_DIR = path.join(__dirname, 'corpus-vex-ledger');

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

// A fixed "now" so overdue detection is deterministic across runs.
const NOW = new Date('2026-07-22T12:00:00.000Z');

// The result is a well-formed Set: every entry a non-empty, upper-case string.
function assertWellFormedSet(ids: Set<string>): void {
  expect(ids).toBeInstanceOf(Set);
  for (const id of ids) {
    expect(typeof id).toBe('string');
    expect(id.length).toBeGreaterThan(0);
    expect(id).toBe(id.toUpperCase());
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('vex-ledger — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('returns an empty set on empty/degenerate inputs', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      expect(recordIds(v as unknown as unknown[]).size).toBe(0);
      expect(activeRecordIds(v as unknown as unknown[], NOW).size).toBe(0);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the invariants',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      const docs = Array.isArray(parsed) ? parsed : [parsed];
      assertWellFormedSet(recordIds(docs));
      const active = activeRecordIds(docs, NOW);
      assertWellFormedSet(active);
      // activeRecordIds can only REMOVE ids vs recordIds (expiry drops some),
      // never add — a monotonicity invariant.
      expect(active.size).toBeLessThanOrEqual(recordIds(docs).size);
    },
  );

  it('never throws on adversarial statements / revisit_by values', () => {
    for (const v of [
      'nope',
      42,
      null,
      { vulnerability: 'x' },
      { vulnerability: { name: 42, aliases: 7 } },
      { vulnerability: { aliases: [null, '', 'GHSA-aaaa-bbbb-cccc'] } },
    ]) {
      expect(() => statementIds(v)).not.toThrow();
    }
    for (const rb of [
      undefined,
      null,
      42,
      '',
      'wait-for-x',
      '2026-13-45',
      '2020-01-01',
    ]) {
      expect(() => isRevisitOverdue(rb, NOW)).not.toThrow();
    }
  });

  it('builds ids from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('CVE-2026-1 GHSA-3jxr-9vmj-r5cp'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6]),
      Buffer.from('x'.repeat(200)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const doc = {
        revisit_by: fdp.consumeString(10),
        statements: [
          {
            vulnerability: {
              name: fdp.consumeString(16),
              aliases: [fdp.consumeString(20)],
            },
            status: fdp.consumeString(12),
          },
        ],
      };
      expect(() => {
        assertWellFormedSet(recordIds([doc]));
        assertWellFormedSet(activeRecordIds([doc], NOW));
      }).not.toThrow();
    }
  });
});
