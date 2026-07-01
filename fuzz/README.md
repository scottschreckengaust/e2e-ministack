# Fuzzing

Fuzzing of the Lambda handler with
[jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js). There are
**two** targets, split by mode — the same handler invariants, different jobs:

| File                         | Mode                 | Job                        | Emits                    |
| ---------------------------- | -------------------- | -------------------------- | ------------------------ |
| `handler.regression.test.js` | regression (replays) | **unit job** (PR gate)     | `reports/junit/fuzz.xml` |
| `handler.fuzz.js`            | fuzzing (generates)  | `fuzz` job (schedule only) | crash artifacts          |

Both assert the same invariants on `event.n` inputs (numbers, strings, integers,
nested objects, undefined):

- the handler never throws, and
- it returns either `200` with a **finite** `doubled`, or a clean `400`.

They complement the [fast-check](https://fast-check.dev) property tests in
`test/unit/lambda.test.ts` (always-on unit gate over structured inputs).

## Regression tier (`handler.regression.test.js`) — PR-gating

This is the **regression** target: it replays every file in the **committed**
seed corpus (`fuzz/corpus/`, plus an empty buffer) through the handler as
ordinary Jest tests, asserting the invariants above. `jest-junit` emits
`reports/junit/fuzz.xml` (one `<testcase>` per input), and the tier runs in the
PR-gating **unit** job — so a corpus input that violates an invariant fails the
tier and blocks the PR.

```bash
npm run test:fuzz-regression   # replays fuzz/corpus/ seeds; writes fuzz.xml
```

It has its **own** Jest config (`jest.fuzz.config.js`) so it never touches the
unit tier's 100% coverage gate or Stryker's programmatic Jest run. It decodes
corpus bytes with jazzer's `FuzzedDataProvider` (imported from
`@jazzer.js/core/dist/FuzzedDataProvider`, the addon-free path) but uses the
**plain Jest runner** — deliberately **not** `@jazzer.js/jest-runner`, which
reaches into Jest's private `Runtime._scriptTransformer` that **Jest 30 removed**
(this repo pins `jest@^30`), throwing and running 0 tests (issue #126). Because
it needs no native libFuzzer addon, this tier runs on **any host** (no GLIBC
floor), unlike the exploratory job below.

## Exploratory fuzzing (`handler.fuzz.js`) — scheduled

`handler.fuzz.js` is the standalone jazzer.js (libFuzzer) target that
**generates** new inputs with coverage feedback.

```bash
npm run fuzz            # time-boxed (60s) local run
```

Requires **GLIBC >= 2.38** (jazzer ships a native libFuzzer binary). Fine on
`ubuntu-latest`; will not run on older hosts. In CI it runs as the `fuzz` job
on a schedule and on manual `workflow_dispatch` — not on every push (fuzzing is
exploratory, not a fast gate).

## What to do with a crash

When the exploratory fuzzer finds an invariant-violating input it writes a
`crash-<hash>` file — the **exact reproducer**. In CI it's uploaded as the
`fuzz-crashes` artifact on a failed run. To triage:

1. **Download** the `fuzz-crashes` artifact from the failed run (or find the
   `crash-*` file locally).
2. **Reproduce** by replaying just that input:

   ```bash
   npx jazzer fuzz/handler.fuzz <path-to-crash-file>
   ```

   jazzer runs the single input and prints the stack / invariant that failed.

3. **Pin it as a regression test** — copy the `crash-*` file into `fuzz/corpus/`
   (the byte format is identical, so the regression tier replays it verbatim)
   and/or add an explicit case in `test/unit/lambda.test.ts`. Either way the bug
   can never silently return: the next PR-gating `test:fuzz-regression` run
   replays it.
4. **Fix** the handler in `lambda/index.js`.
5. **Re-run** `npm run test:fuzz-regression` (fast, any host) to confirm the
   pinned input now passes, and `npm run fuzz` to confirm the fuzzer no longer
   finds it.

The crash file _is_ the failing test case — fuzzing hands you a minimal
reproducer instead of just "something broke."
