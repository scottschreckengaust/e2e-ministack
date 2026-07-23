import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import { endpoint, region } from '../_harness/aws-env';
import { buildSdkPayload, parseInvokePayload } from './invoke';
import type { LambdaContract } from './contract';

/**
 * The typed AWS SDK v3 behavioral oracle for the Lambda vertical (epic #117,
 * sub-issue B / #136). Defined ONCE and reused by every IaC tool — it takes
 * only a {@link LambdaContract} and never knows which tool provisioned the
 * function, which is what keeps it provisioner-blind.
 *
 * Assertions reach parity with the existing `test/integration/integration.test.ts`
 * for both invocation paths:
 *  - happy path `{ n: 21 }` → `doubled === 42`, `statusCode === 200`,
 *    `nodeVersion` matches /^v24\./, no FunctionError, HTTP StatusCode 200;
 *  - handled `{ n: 'abc' }` → payload `statusCode === 400`, no FunctionError
 *    (the handler validates and RETURNS a 400 envelope; it does not throw, so
 *    the invoke still succeeds at the HTTP layer).
 *
 * This is an oracle (`checks.*.ts`): coverage-EXCLUDED (jest.config.js) and run
 * only in the integration tier against a live MiniStack — a THIN I/O shell. The
 * pure payload-encoding / response-parsing (the seam the #136 double-encoding
 * bug lived in) is extracted to the gated {@link ./invoke} module and unit-tested
 * without an emulator; what remains here is genuine I/O: the live
 * `LambdaClient.send(Invoke)` calls and the `expect(...)` assertions on their
 * results (per `services/README.md` § Coverage — extract, don't mock). The
 * endpoint and region come from the shared `_harness/aws-env` module
 * (`AWS_ENDPOINT_URL` / `AWS_DEFAULT_REGION`, set at the CI integration-job level,
 * else the MiniStack defaults); the dummy test/test credentials are accepted by
 * MiniStack.
 */
export async function checkSdk(c: LambdaContract): Promise<void> {
  const lambda = new LambdaClient({
    endpoint: endpoint(process.env),
    region: region(process.env),
  });

  // Happy path: 21 → 42.
  const ok = await lambda.send(
    new InvokeCommand({
      FunctionName: c.functionName,
      Payload: buildSdkPayload({ n: 21 }),
    }),
  );
  // Fail fast on an unhandled Lambda error: with RequestResponse an UNHANDLED
  // throw still returns HTTP 200 with FunctionError:'Unhandled' and an
  // error-envelope payload that has no statusCode. Asserting these first
  // surfaces the real stack trace instead of an opaque undefined-field error.
  expect(ok.FunctionError).toBeUndefined();
  expect(ok.StatusCode).toBe(200);
  const okPayload = parseInvokePayload(ok.Payload!);
  expect(okPayload.statusCode).toBe(200);
  expect(okPayload.doubled).toBe(42);
  expect(okPayload.nodeVersion).toMatch(/^v24\./);

  // Handled 400: non-numeric input returns a 400 envelope, does not throw.
  const bad = await lambda.send(
    new InvokeCommand({
      FunctionName: c.functionName,
      Payload: buildSdkPayload({ n: 'abc' }),
    }),
  );
  expect(bad.FunctionError).toBeUndefined();
  expect(bad.StatusCode).toBe(200);
  const badPayload = parseInvokePayload(bad.Payload!);
  expect(badPayload.statusCode).toBe(400);
}
