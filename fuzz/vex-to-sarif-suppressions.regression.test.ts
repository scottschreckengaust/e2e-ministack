// Plain-Jest *regression* replay of the vex-to-sarif-suppressions fuzz corpus
// (issue #181).
//
// Replays the committed seed corpus (`fuzz/corpus-vex/`) through the VEX ->
// SARIF suppression injector, asserting its invariants. Runs in the PR-gating
// fuzz-regression tier (`jest.fuzz.config.js`) and emits into
// `reports/junit/fuzz.xml`, so a crash input pinned into the corpus becomes a
// permanent regression test. Each corpus buffer is treated as candidate JSON
// (either a SARIF doc or a VEX doc) — the exact input the
// `vex-to-sarif-suppressions.mjs` CLI reads — plus a FuzzedDataProvider-built
// synthetic SARIF/VEX pair, exercising the transform's robustness.
//
// The injector's output GATES the Code-Scanning alert stream via
// advanced-security/dismiss-alerts, so it must never throw and must always
// emit a well-formed SARIF 2.1.0-ish document with an all-or-nothing
// suppressions[] on every result.
import * as fs from 'fs';
import * as path from 'path';
import { FuzzedDataProvider } from '@jazzer.js/core/dist/FuzzedDataProvider';
import {
  injectSuppressions,
  collectSuppressions,
  type SarifLogLike,
  type SarifResultLike,
  type VexDoc,
} from '../.github/scripts/vex-to-sarif-suppressions';

const CORPUS_DIR = path.join(__dirname, 'corpus-vex');

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
 * The injector invariants: never throws; always returns a well-formed doc; and
 * — critically for the dismiss-alerts auto-reverse — EVERY result carries a
 * `suppressions` array (SARIF §3.27.23 all-or-nothing).
 */
function assertInvariants(sarif: unknown, vexDocs: unknown): void {
  const {
    sarif: out,
    covered,
    uncoveredCves,
  } = injectSuppressions(sarif as SarifLogLike, vexDocs as VexDoc[]);
  expect(typeof out).toBe('object');
  expect(Array.isArray(out.runs)).toBe(true);
  expect(typeof covered).toBe('number');
  expect(covered).toBeGreaterThanOrEqual(0);
  expect(Array.isArray(uncoveredCves)).toBe(true);
  for (const run of out.runs as { results?: unknown }[]) {
    if (!run || typeof run !== 'object' || !Array.isArray(run.results))
      continue;
    for (const res of run.results as SarifResultLike[]) {
      if (!res || typeof res !== 'object') continue;
      // Every result MUST have an array suppressions field (possibly empty).
      expect(Array.isArray(res.suppressions)).toBe(true);
      for (const s of res.suppressions!) {
        expect(s.kind).toBe('external');
        expect(typeof s.justification).toBe('string');
      }
    }
  }
}

function tryParse(data: Buffer): unknown {
  try {
    return JSON.parse(data.toString('utf8'));
  } catch {
    return undefined;
  }
}

describe('vex-to-sarif-suppressions — corpus replay (regression)', () => {
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  it('maps empty/degenerate inputs to a valid all-or-nothing SARIF', () => {
    for (const sarif of [undefined, null, {}, { runs: [] }, { runs: 'x' }]) {
      for (const vex of [undefined, null, [], [{}]]) {
        assertInvariants(sarif, vex);
      }
    }
    expect(collectSuppressions([]).size).toBe(0);
  });

  it.each(corpusFiles)(
    'replays corpus input %s without violating the injector invariants',
    (file) => {
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      const parsed = tryParse(data);
      // A corpus buffer may be a SARIF doc OR a VEX doc — feed it as BOTH the
      // sarif arg and (wrapped) the vex arg, so either shape is exercised.
      assertInvariants(parsed, [parsed]);
      assertInvariants(parsed, parsed);
    },
  );

  it('builds a synthetic SARIF+VEX pair from fuzzed bytes and injects safely', () => {
    for (const seed of [
      Buffer.from('CVE-2026-11822: not_affected'),
      Buffer.from([0, 255, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
      Buffer.from('x'.repeat(500)),
    ]) {
      const fdp = new FuzzedDataProvider(seed.length ? seed : Buffer.from([0]));
      const cveNum = fdp.consumeIntegralInRange(1, 99999);
      const ruleId = `CVE-2026-${cveNum}-${fdp.consumeString(8)}`;
      const status = fdp.consumeString(16);
      const sarif: SarifLogLike = {
        version: '2.1.0',
        runs: [{ results: [{ ruleId } as SarifResultLike] }],
      };
      const vex: VexDoc = {
        statements: [
          {
            vulnerability: { name: `CVE-2026-${cveNum}` },
            status,
            justification: fdp.consumeString(16),
            impact_statement: fdp.consumeString(32),
          },
        ],
      };
      assertInvariants(sarif, [vex]);
    }
  });

  it('never throws on adversarial parsed values', () => {
    const nasties: [unknown, unknown][] = [
      [42, 42],
      ['a string', 'a string'],
      [
        [1, 2, 3],
        [1, 2, 3],
      ],
      [{ runs: [null, 7, { results: 'nope' }] }, [{ statements: 'x' }]],
      [
        { runs: [{ results: [null, {}, { ruleId: 42 }] }] },
        [{ statements: [null] }],
      ],
      [{ runs: [{ results: [{ ruleId: 'CVE-2026-1-x' }] }] }, 'not-an-array'],
    ];
    for (const [sarif, vex] of nasties) {
      expect(() =>
        injectSuppressions(sarif as SarifLogLike, vex as VexDoc[]),
      ).not.toThrow();
    }
  });
});
