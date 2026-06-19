import { handler } from '../../lambda/index';

// Pure-logic unit tests for the Lambda handler — no AWS, no MiniStack, no
// Docker. Exercises the doubling logic and its edge cases directly.
describe('cdk-doubler handler', () => {
  it('doubles a positive number', async () => {
    const res = await handler({ n: 21 });
    expect(res).toEqual({ statusCode: 200, doubled: 42, nodeVersion: process.version });
  });

  it('doubles zero', async () => {
    const res = await handler({ n: 0 });
    expect(res.doubled).toBe(0);
  });

  it('handles negative numbers', async () => {
    const res = await handler({ n: -5 });
    expect(res.doubled).toBe(-10);
  });

  it('defaults missing n to 0', async () => {
    const res = await handler({});
    expect(res.doubled).toBe(0);
  });

  it('always returns statusCode 200', async () => {
    const res = await handler({ n: 7 });
    expect(res.statusCode).toBe(200);
  });
});
