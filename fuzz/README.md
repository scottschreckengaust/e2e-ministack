# Fuzzing

Coverage-guided fuzzing of the Lambda handler with
[jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js) (libFuzzer).

`handler.fuzz.js` feeds the handler fuzzer-generated `event.n` values (numbers,
strings, integers, nested objects, undefined) and asserts two invariants:

- the handler never throws, and
- it returns either `200` with a **finite** `doubled`, or a clean `400`.

This complements the [fast-check](https://fast-check.dev) property tests in
`test/unit/lambda.test.ts`: fast-check asserts logical invariants over
structured inputs (always-on unit gate); jazzer mutates raw bytes with coverage
feedback to reach states the structured generators may miss.

## Running

```bash
npm run fuzz            # time-boxed (60s) local run
```

Requires **GLIBC >= 2.38** (jazzer ships a native libFuzzer binary). Fine on
`ubuntu-latest`; will not run on older hosts. In CI it runs as the `fuzz` job
on a schedule and on manual `workflow_dispatch` — not on every push (fuzzing is
exploratory, not a fast gate).

## What to do with a crash

When the fuzzer finds an invariant-violating input it writes a `crash-<hash>`
file — the **exact reproducer**. In CI it's uploaded as the `fuzz-crashes`
artifact on a failed run. To triage:

1. **Download** the `fuzz-crashes` artifact from the failed run (or find the
   `crash-*` file locally).
2. **Reproduce** by replaying just that input:

   ```bash
   npx jazzer fuzz/handler.fuzz <path-to-crash-file>
   ```

   jazzer runs the single input and prints the stack / invariant that failed.

3. **Pin it as a regression test** — decode the input and add it as an explicit
   case in `test/unit/lambda.test.ts` so the bug can never silently return.
4. **Fix** the handler in `lambda/index.js`.
5. **Re-run** `npm run fuzz` to confirm the crash is gone; optionally keep the
   crash file in a committed seed corpus so future runs always re-check it.

The crash file _is_ the failing test case — fuzzing hands you a minimal
reproducer instead of just "something broke."
