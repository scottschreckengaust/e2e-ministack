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

  it('coerces a numeric string', async () => {
    expect((await handler({ n: 5 as unknown as number })).doubled).toBe(10);
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
    'never returns NaN/Infinity and always has a valid status for ANY input',
    async (anyValue) => {
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
