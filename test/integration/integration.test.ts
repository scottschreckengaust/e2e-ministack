import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
} from '@aws-sdk/client-s3';

/**
 * Integration tests against resources deployed by `cdklocal deploy` into
 * MiniStack. The workflow runs `cdk deploy` BEFORE `jest`, so these tests
 * assume `cdk-doubler` and `cdk-demo-bucket` already exist.
 *
 * AWS_ENDPOINT_URL (set in the workflow env) points every SDK client at
 * MiniStack; the dummy test/test credentials are accepted by the emulator.
 * forcePathStyle is required for S3 against a single-host emulator.
 */
const endpoint = process.env.AWS_ENDPOINT_URL ?? 'http://localhost:4566';
const region = process.env.AWS_DEFAULT_REGION ?? 'us-east-1';

const lambda = new LambdaClient({ endpoint, region });
const s3 = new S3Client({ endpoint, region, forcePathStyle: true });

describe('MiniStack CDK integration', () => {
  it('invokes the deployed Lambda and gets the doubled value', async () => {
    const res = await lambda.send(
      new InvokeCommand({
        FunctionName: 'cdk-doubler',
        Payload: Buffer.from(JSON.stringify({ n: 21 })),
      }),
    );
    // Fail fast on an unhandled Lambda error: with the default RequestResponse
    // invocation type an UNHANDLED throw still returns HTTP 200 at the SDK
    // layer with FunctionError:'Unhandled' and an error-envelope payload
    // ({errorType,errorMessage,trace}) that has no `statusCode`. Asserting
    // these first surfaces the real stack trace instead of an opaque
    // "payload.statusCode is undefined" failure further down.
    expect(res.FunctionError).toBeUndefined();
    expect(res.StatusCode).toBe(200);
    const payload = JSON.parse(Buffer.from(res.Payload!).toString());
    expect(payload.statusCode).toBe(200);
    expect(payload.doubled).toBe(42);
    // Confirm the function actually ran on the Node 24 runtime.
    expect(payload.nodeVersion).toMatch(/^v24\./);
  });

  it('returns a handled 400 for non-numeric input (no FunctionError)', async () => {
    // The handler validates input shape and *returns* a 400 envelope for a
    // non-finite `n` (e.g. Number('abc') -> NaN); it does not throw. So the
    // SDK call succeeds (StatusCode 200, FunctionError undefined) and the
    // 400 lives in the parsed payload, not the HTTP/invoke layer.
    const res = await lambda.send(
      new InvokeCommand({
        FunctionName: 'cdk-doubler',
        Payload: Buffer.from(JSON.stringify({ n: 'abc' })),
      }),
    );
    expect(res.FunctionError).toBeUndefined();
    expect(res.StatusCode).toBe(200);
    const payload = JSON.parse(Buffer.from(res.Payload!).toString());
    expect(payload.statusCode).toBe(400);
  });

  it('round-trips an object through the deployed S3 bucket', async () => {
    const Bucket = 'cdk-demo-bucket';
    const Key = 'hello.txt';
    await s3.send(new PutObjectCommand({ Bucket, Key, Body: 'hi from test' }));
    const got = await s3.send(new GetObjectCommand({ Bucket, Key }));
    const body = await got.Body!.transformToString();
    expect(body).toBe('hi from test');
  });
});
