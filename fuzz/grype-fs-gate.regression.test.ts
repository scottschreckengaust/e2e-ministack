// Plain-Jest *regression* replay of the grype-fs-gate fuzz corpus (#284).
//
// Replays the committed seed corpus (`fuzz/corpus-grype-fs-gate/`) through the
// VEX-aware Grype-FS gate decider, asserting its invariants. Runs in the
// PR-gating fuzz-regression tier (`jest.fuzz.config.js`). This module decides
// whether the REQUIRED Grype FS check reds, so it must never throw on a
// malformed/partial grype JSON and must always return a well-formed, sorted,
// deduped array of uncovered high+ ids.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  uncoveredVulns,
  matchVulnIds,
  matchPurl,
} from '../.github/scripts/grype-fs-gate';
import { recordAcceptances } from '../.github/scripts/vex-ledger';

const CORPUS_DIR = path.join(__dirname, 'corpus-grype-fs-gate');

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

// The 3 mcp records as the gate sees them — the real #284 acceptance (CVE names +
// GHSA aliases) scoped to the pypi product each argues about (#337), so the
// corpus replay exercises BOTH the aliasing and the surface-matching paths.
const MCP_PURL = 'pkg:pypi/mcp@1.23.3';
const MCP_ACCEPTED = recordAcceptances([
  {
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-52869',
          aliases: ['GHSA-jpw9-pfvf-9f58'],
        },
        products: [{ '@id': MCP_PURL, identifiers: { purl: MCP_PURL } }],
        status: 'affected',
      },
    ],
  },
  {
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-52870',
          aliases: ['GHSA-hvrp-rf83-w775'],
        },
        products: [{ '@id': MCP_PURL, identifiers: { purl: MCP_PURL } }],
        status: 'affected',
      },
    ],
  },
  {
    statements: [
      {
        vulnerability: {
          name: 'CVE-2026-59950',
          aliases: ['GHSA-vj7q-gjh5-988w'],
        },
        products: [{ '@id': MCP_PURL, identifiers: { purl: MCP_PURL } }],
        status: 'affected',
      },
    ],
  },
]);

// The gate result is a well-formed list: every entry a non-empty string, the
// array sorted ascending, and deduped.
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

describe('grype-fs-gate — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('returns an empty (passing) list on empty/degenerate inputs', () => {
    for (const v of [undefined, null, {}, [], 'x', 42]) {
      expect(uncoveredVulns(v, MCP_ACCEPTED)).toEqual([]);
    }
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the invariants',
    (file) => {
      const parsed = tryParse(
        fs.readFileSync(path.join(CORPUS_DIR, sanitizeCorpusName(file))),
      );
      assertWellFormed(uncoveredVulns(parsed, MCP_ACCEPTED));
      // No acceptances is fail-closed: never fewer uncovered than with the mcp
      // set (an acceptance can only REMOVE entries, never add).
      const withEmpty = uncoveredVulns(parsed, []);
      assertWellFormed(withEmpty);
      expect(withEmpty.length).toBeGreaterThanOrEqual(
        uncoveredVulns(parsed, MCP_ACCEPTED).length,
      );
    },
  );

  it('builds a synthetic grype JSON from fuzzed bytes and never throws', () => {
    for (const seed of [
      Buffer.from('CVE-2026-1 GHSA-jpw9-pfvf-9f58'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8]),
      Buffer.from('x'.repeat(300)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const n = fdp.consumeIntegralInRange(1, 9999);
      const doc = {
        matches: [
          {
            vulnerability: {
              id: `CVE-2099-${n}`,
              severity: fdp.consumeString(8),
            },
            relatedVulnerabilities: [{ id: fdp.consumeString(12) }],
          },
          { vulnerability: fdp.consumeString(6) },
          42,
        ],
      };
      expect(() =>
        assertWellFormed(uncoveredVulns(doc, MCP_ACCEPTED)),
      ).not.toThrow();
    }
  });

  it('never throws on adversarial parsed values', () => {
    for (const v of [
      { matches: 42 },
      { matches: ['x', 7, null] },
      { matches: [{ vulnerability: 'nope' }] },
      { matches: [{ vulnerability: { id: ['CVE-2026-1'], severity: 5 } }] },
      'not-an-object',
      [1, 2, 3],
    ]) {
      expect(() => uncoveredVulns(v, MCP_ACCEPTED)).not.toThrow();
      expect(() => matchVulnIds(v)).not.toThrow();
      expect(() => matchPurl(v)).not.toThrow();
    }
  });

  it('never throws reading an adversarial artifact purl (#337 surface parsing)', () => {
    // The purl comparison is the newest decision in the gate, so its parser gets
    // the fuzz tier's totality guarantee too: every one of these must yield a
    // value (or null) rather than throwing — `%zz` in particular would throw from
    // a naive decodeURIComponent.
    for (const purl of [
      '',
      'pkg:',
      'pkg:/',
      'pkg://npm/x',
      'pkg:npm',
      'pkg:npm/',
      'pkg:npm/%zz',
      'pkg:npm/x@%zz',
      'pkg:npm/x?%zz=1',
      'pkg:npm/@scope/x@1.0.0',
      'pkg:npm/x@1.0.0?a=1&&=2&b&c=',
      'pkg:npm/x@1.0.0#/sub/path',
      `pkg:npm/${'a'.repeat(5000)}@1.0.0`,
      'pkg:npm/x@1.0.0?a=' + '%'.repeat(500),
      '\0pkg:npm/x',
      'PKG:NPM/X@1.0.0',
    ]) {
      expect(() => matchPurl({ artifact: { purl } })).not.toThrow();
    }
  });

  it('never throws building the acceptances from adversarial VEX docs', () => {
    for (const v of [
      undefined,
      null,
      'x',
      [{ statements: 'nope' }],
      [{ statements: [{ vulnerability: { name: 42, aliases: 7 } }] }],
      [
        {
          statements: [{ vulnerability: { name: 'CVE-1' }, products: 'nope' }],
        },
      ],
      [
        {
          statements: [
            { vulnerability: { name: 'CVE-1' }, products: [null, 7] },
          ],
        },
      ],
      [
        {
          statements: [
            {
              vulnerability: { name: 'CVE-1' },
              products: [{ '@id': 42, identifiers: 'nope' }],
            },
          ],
        },
      ],
    ]) {
      expect(() => recordAcceptances(v as unknown as unknown[])).not.toThrow();
    }
  });
});
