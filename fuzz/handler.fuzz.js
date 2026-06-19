// Coverage-guided fuzz target for the Lambda handler (jazzer.js / libFuzzer).
// Run: npm run fuzz  (time-boxed in CI; runs longer locally / on demand)
//
// Complements the fast-check property tests: jazzer mutates raw bytes and uses
// coverage feedback to reach states the structured generators may not. The
// invariant is the same — the handler must never throw and must always return
// a finite `doubled` (200) or a clean 400.
const { handler } = require('../lambda/index.js');

/**
 * @param {import('@jazzer.js/core').FuzzedDataProvider} data
 */
module.exports.fuzz = async (data) => {
  // Derive a variety of `event.n` shapes from the fuzzer's bytes so it can
  // explore numeric, string, and structural inputs.
  const choice = data.consumeIntegralInRange(0, 4);
  let n;
  switch (choice) {
    case 0:
      n = data.consumeNumber();
      break;
    case 1:
      n = data.consumeString(32);
      break;
    case 2:
      n = data.consumeIntegral(8);
      break;
    case 3:
      n = { nested: data.consumeString(8) };
      break;
    default:
      n = undefined;
  }

  const res = await handler({ n });

  // Invariants — a violation throws and jazzer records a finding.
  if (res.statusCode !== 200 && res.statusCode !== 400) {
    throw new Error(`unexpected statusCode: ${res.statusCode}`);
  }
  if (res.statusCode === 200 && !Number.isFinite(res.doubled)) {
    throw new Error(`200 with non-finite doubled: ${res.doubled}`);
  }
};
