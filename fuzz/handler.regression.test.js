// Plain-Jest *regression* replay of the fuzz corpus for the Lambda handler.
//
// This is the PR-gating sibling of the exploratory `handler.fuzz.js`:
//   - `handler.fuzz.js` (standalone jazzer CLI, `module.exports.fuzz`) runs in
//     the schedule-only `fuzz` CI job — coverage-guided, time-boxed, GENERATES
//     new inputs. Exploratory, not a fast gate; needs the native libFuzzer
//     addon (GLIBC >= 2.38).
//   - THIS file REPLAYS the committed seed corpus (`fuzz/corpus/`) as ordinary
//     Jest tests. It runs in the PR-gating unit path via its own Jest config
//     (`jest.fuzz.config.js`, `npm run test:fuzz-regression`), and jest-junit
//     emits `reports/junit/fuzz.xml`. A corpus input that violates a handler
//     invariant fails the tier — so known crash inputs, pinned into the corpus,
//     become permanent PR regression tests.
//
// WHY PLAIN JEST (not @jazzer.js/jest-runner): that runner reaches into Jest's
// private `Runtime._scriptTransformer`, which Jest 30 removed — it throws and
// runs 0 tests on this repo's pinned jest@^30 (issue #126). Replaying the corpus
// as a normal Jest test needs none of the runner's machinery: we only need
// jazzer's `FuzzedDataProvider` to decode a corpus buffer the same way the
// standalone target does. Importing it from `@jazzer.js/core/dist/`
// FuzzedDataProvider avoids `@jazzer.js/core`'s index, which eagerly loads the
// native libFuzzer addon — so this tier runs on ANY host (no GLIBC-2.38 floor),
// unlike the exploratory job.
const fs = require('fs');
const path = require('path');
const {
  FuzzedDataProvider,
} = require('@jazzer.js/core/dist/FuzzedDataProvider');
const { handler } = require('../lambda/index.js');

// The committed seed corpus. Each file is a raw byte input; a jazzer `crash-*`
// reproducer can be dropped in here verbatim to pin it as a regression test.
const CORPUS_DIR = path.join(__dirname, 'corpus');
// CORPUS_DIR is a fixed, committed in-repo directory and its entries come from
// readdirSync of that directory — there is no external/user input and no path
// traversal is reachable. Semgrep's path-join-resolve-traversal rule treats the
// readdir entry (a callback parameter) as a taint source and recognizes no
// sanitizer for a trusted directory listing, so it is a false positive here.
// Suppress that ONE rule on the specific sink line rather than add runtime path
// validation to test-only code for a non-threat.
const corpusFiles = fs
  .readdirSync(CORPUS_DIR)
  // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
  .filter((entry) => fs.statSync(path.join(CORPUS_DIR, entry)).isFile())
  .sort();

/**
 * Decode a corpus buffer into an `event.n` value, mirroring the byte-consumption
 * of the standalone `handler.fuzz.js` target so the two exercise the same shapes
 * (number / numeric-or-arbitrary string / integral / nested object / undefined).
 * @param {Buffer} data raw corpus bytes
 * @returns {unknown} the derived `event.n`
 */
function decodeEventN(data) {
  const fdp = new FuzzedDataProvider(data);
  const choice = fdp.consumeIntegralInRange(0, 4);
  switch (choice) {
    case 0:
      return fdp.consumeNumber();
    case 1:
      return fdp.consumeString(32);
    case 2:
      return fdp.consumeIntegral(6); // jazzer.js caps maxNumBytes at 6
    case 3:
      return { nested: fdp.consumeString(8) };
    default:
      return undefined;
  }
}

/**
 * Assert the handler's invariants for a single corpus input. These are the SAME
 * invariants the standalone jazzer target asserts: the handler never throws, and
 * returns either a 200 with a finite `doubled` or a clean 400 (non-empty error,
 * no `doubled`), with a non-empty `nodeVersion` on every branch. A violation
 * fails the replayed test — that is how a crashing corpus input gates the PR.
 * @param {Buffer} data raw corpus bytes
 */
async function assertInvariants(data) {
  const n = decodeEventN(data);
  const res = await handler({ n });

  expect([200, 400]).toContain(res.statusCode);
  expect(typeof res.nodeVersion).toBe('string');
  expect(res.nodeVersion).not.toBe('');

  if (res.statusCode === 200) {
    expect(Number.isFinite(res.doubled)).toBe(true);
  } else {
    expect(typeof res.error).toBe('string');
    expect(res.error).not.toBe('');
    expect(res.doubled).toBeUndefined();
  }
}

describe('cdk-doubler handler — corpus replay (regression)', () => {
  // Guard: an empty corpus would make this tier silently vacuous. Fail loudly.
  it('has a non-empty committed seed corpus', () => {
    expect(corpusFiles.length).toBeGreaterThan(0);
  });

  // Always replay the empty-buffer edge case (mirrors the jazzer runner, which
  // also runs the target once with an empty input).
  it('replays the empty input without violating handler invariants', async () => {
    await assertInvariants(Buffer.from(''));
  });

  // One reported <testcase> per corpus file, so jest-junit's fuzz.xml lists each
  // replayed input individually and a single bad input pinpoints itself.
  it.each(corpusFiles)(
    'replays corpus input %s without violating handler invariants',
    async (file) => {
      // `file` is a committed-corpus entry from readdirSync (see the note at
      // CORPUS_DIR) — trusted, not user input. Same Semgrep false positive.
      // nosemgrep: javascript.lang.security.audit.path-traversal.path-join-resolve-traversal.path-join-resolve-traversal
      const data = fs.readFileSync(path.join(CORPUS_DIR, file));
      await assertInvariants(data);
    },
  );
});
