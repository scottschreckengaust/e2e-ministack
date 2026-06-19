import { test as fcTest, fc } from '@fast-check/jest';
import { handler } from '../../lambda/index';

// Example-based unit tests for the Lambda handler — no AWS, no MiniStack.
describe('cdk-doubler handler — examples', () => {
  it('doubles a positive number', async () => {
    const res = await handler({ n: 21 });
    expect(res).toEqual({
      statusCode: 200,
      doubled: 42,
      nodeVersion: process.version,
    });
  });

  it('doubles zero', async () => {
    expect((await handler({ n: 0 })).doubled).toBe(0);
  });

  it('handles negative numbers', async () => {
    expect((await handler({ n: -5 })).doubled).toBe(-10);
  });

  // A real numeric *string* is accepted and doubled (the handler accepts
  // number | non-empty-numeric-string). Surrounding whitespace is tolerated.
  it.each([
    ['5', 10],
    ['  21 ', 42],
    ['-5', -10],
  ])('doubles a numeric string %p to %p', async (str, expected) => {
    const res = await handler({ n: str as unknown as number });
    expect(res.statusCode).toBe(200);
    expect(res.doubled).toBe(expected);
  });

  // Non-numeric / non-finite input → 400 "must be a finite number".
  it.each([['abc'], [{}], [NaN], [Infinity], [-Infinity], [undefined]])(
    'rejects non-finite/non-numeric input %p with the not-finite error',
    async (bad) => {
      const res = await handler({ n: bad as unknown as number });
      expect(res.statusCode).toBe(400);
      expect(res.doubled).toBeUndefined();
      expect(res.error).toBe('event.n must be a finite number');
    },
  );

  // Finite but overflows when doubled → distinct 400 "too large" message.
  it('rejects a finite number that overflows when doubled', async () => {
    const res = await handler({ n: 1e308 });
    expect(res.statusCode).toBe(400);
    expect(res.error).toBe('event.n is too large to double');
  });

  // Issue #8: structurally-invalid inputs that Number() *silently coerces*
  // ([] -> 0, [5] -> 5, true -> 1, '' -> 0, '  ' -> 0) must be REJECTED (400),
  // not blessed as a 200 success. The handler is the system-under-test for the
  // whole pyramid; "doubling an empty array to 0" is exactly what a doubler
  // reference should not silently accept.
  it.each([
    ['empty array', []],
    ['single-element array', [5]],
    ['boolean true', true],
    ['boolean false', false],
    ['empty string', ''],
    ['whitespace string', '   '],
  ])(
    'rejects structurally-invalid input (%s) with the not-finite 400',
    async (_label, bad) => {
      const res = await handler({ n: bad as unknown as number });
      expect(res.statusCode).toBe(400);
      expect(res.doubled).toBeUndefined();
      expect(res.error).toBe('event.n must be a finite number');
    },
  );

  // Hard regression for the mutation-CI failure: non-coercible values make
  // Number(x) THROW ("Cannot convert object to primitive value", or a Symbol
  // TypeError) instead of returning NaN. The handler must treat that class as
  // a clean 400 and never throw. The {toString:0} case is the exact
  // counterexample fast-check found at seed -1793157300.
  it.each([
    ['Symbol', Symbol('x')],
    ['null-prototype object', Object.create(null)],
    ['object with non-callable toString', { toString: 0 }],
    ['object with non-callable valueOf+toString', { valueOf: 1, toString: 2 }],
  ])(
    'returns a clean 400 (never throws) for a non-coercible input (%s)',
    async (_label, bad) => {
      const res = await handler({ n: bad as unknown as number });
      expect(res.statusCode).toBe(400);
      expect(res.doubled).toBeUndefined();
      expect(res.error).toBe('event.n must be a finite number');
    },
  );

  // A null/undefined event must not throw — it's rejected like missing n.
  it.each([[null], [undefined], [{}]])(
    'treats a missing/empty event %p as not-finite (400)',
    async (evt) => {
      const res = await handler(evt as unknown as { n?: number });
      expect(res.statusCode).toBe(400);
      expect(res.error).toBe('event.n must be a finite number');
    },
  );
});

// Property-based tests: assert invariants across thousands of generated inputs.
describe('cdk-doubler handler — properties', () => {
  fcTest.prop([fc.double({ noNaN: true, noDefaultInfinity: true })])(
    'any finite number either doubles to a finite number (200) or is rejected (400)',
    async (n) => {
      const res = await handler({ n });
      if (res.statusCode === 200) {
        // success invariant: doubled is finite and exactly 2n
        expect(Number.isFinite(res.doubled)).toBe(true);
        expect(res.doubled).toBe(n * 2);
      } else {
        // only overflow (2n non-finite) may be rejected for a finite n
        expect(res.statusCode).toBe(400);
        expect(Number.isFinite(n * 2)).toBe(false);
      }
    },
  );

  fcTest.prop([fc.anything()])(
    'never throws and always has a valid status for ANY input',
    async (anyValue) => {
      // The handler must NEVER throw — even for non-coercible inputs like
      // Symbols or {toString:0} where Number(x) raises a TypeError. Awaiting
      // inside the property turns any throw into a clean test failure here.
      const res = await handler({ n: anyValue as unknown as number });
      expect([200, 400]).toContain(res.statusCode);
      if (res.statusCode === 200) {
        expect(Number.isFinite(res.doubled)).toBe(true);
      } else {
        expect(res.doubled).toBeUndefined();
      }
    },
  );

  fcTest.prop([fc.integer({ min: -1_000_000, max: 1_000_000 })])(
    'integers in a safe range always succeed and equal 2n',
    async (n) => {
      const res = await handler({ n });
      expect(res.statusCode).toBe(200);
      expect(res.doubled).toBe(n * 2);
    },
  );
});
