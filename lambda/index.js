// Doubles event.n. Hardened against non-numeric / non-finite input (found by
// fuzzing): coerces the input, rejects anything that doesn't yield a finite
// number with a 400, and guarantees a finite `doubled` on success.
const ERR_NOT_FINITE = 'event.n must be a finite number';
const ERR_TOO_LARGE = 'event.n is too large to double';

exports.handler = async (event) => {
  // Number(undefined) -> NaN, Number(null) -> 0, Number('5') -> 5,
  // Number('abc'|{}) -> NaN. The optional chain handles a null/undefined event.
  const n = Number(event?.n);

  if (!Number.isFinite(n)) {
    return {
      statusCode: 400,
      error: ERR_NOT_FINITE,
      nodeVersion: process.version,
    };
  }

  const doubled = n * 2;
  if (!Number.isFinite(doubled)) {
    // n was finite but 2n overflows to Infinity (e.g. n ~ 1e308).
    return {
      statusCode: 400,
      error: ERR_TOO_LARGE,
      nodeVersion: process.version,
    };
  }

  return { statusCode: 200, doubled, nodeVersion: process.version };
};
