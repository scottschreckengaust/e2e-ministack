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

/**
 * Confine a corpus filename to CORPUS_DIR before it is joined onto a filesystem
 * path. Every read below routes through this so no name can escape the corpus
 * directory: any value that is not a single, plain path segment is rejected
 * outright (see the inline notes for the exact surfaces — separators under both
 * OS conventions, `.`/`..`, NUL byte, and `:`). In this test the names come from
 * `readdirSync(CORPUS_DIR)` so they are already safe — but validating at the join
 * site keeps the guarantee local and explicit rather than relying on the caller,
 * and is the real sanitizer the path-traversal SAST rule looks for (a
 * `sanitize`-named validator on the value entering `path.join`).
 *
 * Bespoke by design (per docs/SECURITY-TOOLING.md "Remediating a scanner
 * finding"): this is built only on the vetted stdlib primitives
 * `path.win32.basename`/`path.posix.basename` and REJECTS rather than mutates.
 * A drop-in library like `sanitize-filename` STRIPS bad characters and returns a
 * different name — which for a corpus read would silently open the wrong file,
 * worse than failing — so no vetted library fits this sink's exact semantics.
 * @param {string} name a corpus filename to validate
 * @returns {string} the same name, guaranteed to be a single safe path segment
 */
function sanitizeCorpusName(name) {
  // Validate under BOTH OS conventions so the guard is correct regardless of the
  // host: `path.basename`'s separator set is platform-dependent (`\` separates on
  // Windows but not POSIX), so we check `path.win32.basename` AND
  // `path.posix.basename` — a name must be a single plain segment under each. We
  // also reject, explicitly:
  //   • `.` / `..`            — directory-relative escapes
  //   • a NUL byte (`\0`)     — classic null-byte truncation (OWASP), which can
  //                             cut a path short past a suffix check
  //   • a colon (`:`)         — Windows drive (`C:`) and NTFS alternate-data-stream
  //                             (`name:stream`) selectors
  // What survives is a single, plain path segment that cannot escape CORPUS_DIR.
  // NOTE (scope): this guards a FILESYSTEM name. URL-percent-encoded forms
  // (`%2e%2e%2f`, overlong UTF-8 `%c0%af`, …) are a decode-layer concern and do
  // not apply here — nothing URL-decodes these names before the read — so a raw
  // `%2e%2e%2f` is just an ordinary (harmless) filename to `fs`, not a bypass.
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
      // Route the name through the same containment check before the read, so
      // the join can never escape CORPUS_DIR.
      const data = fs.readFileSync(
        path.join(CORPUS_DIR, sanitizeCorpusName(file)),
      );
      await assertInvariants(data);
    },
  );
});

describe('sanitizeCorpusName — path-traversal containment', () => {
  // Prove the guard actually blocks escapes rather than just satisfying the
  // scanner: every value that is not a single, plain path segment is rejected,
  // so a name can never resolve outside CORPUS_DIR. Corpus of attack surfaces
  // drawn from OWASP "Path Traversal"
  // (https://owasp.org/www-community/attacks/Path_Traversal), scoped to the
  // forms that reach a filesystem name (no URL-decode layer sits in front here).
  it.each([
    // — POSIX relative traversal —
    '../../etc/passwd',
    '../../../../etc/shadow',
    '..',
    '.',
    './x',
    'sub/dir',
    // — Windows backslash traversal (must be caught even on POSIX hosts) —
    'a\\b',
    '..\\..\\x',
    '..\\..\\..\\Windows\\win.ini',
    // — absolute paths (both OS) —
    '/abs/path',
    '/etc/passwd',
    'C:\\Windows\\System32\\drivers\\etc\\hosts',
    // — Windows drive / NTFS alternate-data-stream via colon —
    'C:file',
    'name:stream',
    // — null-byte truncation (OWASP): would defeat a naive suffix check —
    'secret.doc\0.pdf',
    'a\0',
    // — trailing/leading separator forms —
    'dir/',
    '/leading',
  ])('rejects the traversal attempt %p', (evil) => {
    expect(() => sanitizeCorpusName(evil)).toThrow(/path traversal/);
  });

  // Non-string / empty inputs must also be rejected, not coerced.
  it.each([
    ['', 'empty string'],
    [undefined, 'undefined'],
    [null, 'null'],
  ])('rejects the non-name input (%s)', (evil) => {
    expect(() => sanitizeCorpusName(evil)).toThrow(/path traversal/);
  });

  // Legitimate single-segment names — including a jazzer `crash-*` reproducer
  // filename — pass unchanged. NB: a raw URL-encoded string like `%2e%2e%2f` is
  // NOT a bypass here (nothing decodes it), so it is simply a valid filename;
  // we deliberately don't assert it as "malicious" — that would misrepresent
  // the guard's actual (filesystem-layer) responsibility.
  it.each([
    'crash-abc123',
    'number-double',
    'nested-object',
    'a.b_c-1',
    'file.bin',
  ])('accepts the legitimate corpus name %p', (ok) => {
    expect(sanitizeCorpusName(ok)).toBe(ok);
  });
});
