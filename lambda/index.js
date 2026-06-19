// Doubles event.n. Validated against non-numeric / non-finite / non-coercible
// input: accepts only a real number or a non-empty string, rejects everything
// else with a 400, and guarantees a finite `doubled` on success. Never throws.
const ERR_NOT_FINITE = 'event.n must be a finite number';
const ERR_TOO_LARGE = 'event.n is too large to double';

exports.handler = async (event) => {
  const raw = event?.n;

  // Validate the shape BEFORE coercing. Number() is doubly unsafe on raw input:
  // it silently coerces structurally-invalid values ([] -> 0, [5] -> 5,
  // true -> 1, '' -> 0) into bogus "successes", and it THROWS on non-coercible
  // values (a Symbol, or an object with a non-callable valueOf/toString such as
  // {toString:0}) -> "Cannot convert object to primitive value". Accept only a
  // real number or a non-empty/whitespace string, so a numeric string ('5')
  // still doubles while every other shape is rejected as a clean 400. This
  // allowlist also guarantees the Number() call below can never throw.
  const isNumber = typeof raw === 'number';
  const isNumericString = typeof raw === 'string' && raw.trim() !== '';
  if (!isNumber && !isNumericString) {
    return {
      statusCode: 400,
      error: ERR_NOT_FINITE,
      nodeVersion: process.version,
    };
  }

  // Safe now: Number(number) is identity, Number(string) returns NaN (never
  // throws) for non-numeric text like 'abc'. NaN/Infinity fall through to 400.
  const n = Number(raw);
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
