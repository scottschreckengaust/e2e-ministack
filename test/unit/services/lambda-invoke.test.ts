import {
  buildSdkPayload,
  parseInvokePayload,
  cliInvokeArgs,
} from '../../../services/lambda/invoke';

// Unit test for the Lambda oracle's PURE invoke logic (#151 / #144). This is
// the fast-tier safety net for the payload-encoding + response-parsing that used
// to live INSIDE the coverage-excluded `checks.*.ts` oracles — the exact class
// of pure logic that hid the #136 AWS-CLI-v2 double-encoding bug (a base64
// `--payload` under `raw-in-base64-out` ⇒ the CLI forwards the base64 TEXT
// verbatim ⇒ the handler JSON.parses it ⇒ `n` is NaN ⇒ a bogus 400). Extracting
// it here (a NON-`checks.*.ts` module → coverage-INCLUDED) makes that seam
// unit-testable without an emulator and locks the #136 regression permanently.
// The genuine I/O (LambdaClient.send / execFile) stays in the excluded shells.
// Every branch is table-driven so the module holds the repo's 100% gate.

describe('services/lambda/invoke — buildSdkPayload', () => {
  it('serializes the input object to a UTF-8 JSON byte buffer', () => {
    const bytes = buildSdkPayload({ n: 21 });
    expect(Buffer.from(bytes).toString('utf8')).toBe('{"n":21}');
  });

  it('round-trips a non-numeric input verbatim (no coercion)', () => {
    const bytes = buildSdkPayload({ n: 'abc' });
    expect(Buffer.from(bytes).toString('utf8')).toBe('{"n":"abc"}');
  });
});

describe('services/lambda/invoke — parseInvokePayload', () => {
  it('decodes a happy-path 200 envelope from an SDK Payload buffer', () => {
    const raw = Buffer.from(
      JSON.stringify({ statusCode: 200, doubled: 42, nodeVersion: 'v24.1.0' }),
    );
    const out = parseInvokePayload(raw);
    expect(out).toEqual({
      statusCode: 200,
      doubled: 42,
      nodeVersion: 'v24.1.0',
    });
  });

  it('decodes a handled-400 envelope (no doubled/nodeVersion)', () => {
    const raw = Buffer.from(JSON.stringify({ statusCode: 400 }));
    const out = parseInvokePayload(raw);
    expect(out.statusCode).toBe(400);
    expect(out.doubled).toBeUndefined();
    expect(out.nodeVersion).toBeUndefined();
  });

  it('accepts a Uint8Array (SDK Payload type) as well as a Buffer', () => {
    const raw = new TextEncoder().encode(
      JSON.stringify({ statusCode: 200, doubled: 8 }),
    );
    expect(parseInvokePayload(raw).doubled).toBe(8);
  });

  it('accepts a UTF-8 string (the CLI temp-file body path)', () => {
    // The CLI oracle reads its invoke output file as a string and parses it
    // through here; the SDK oracle passes a Uint8Array. Cover the string branch.
    const out = parseInvokePayload(
      JSON.stringify({ statusCode: 200, doubled: 42, nodeVersion: 'v24.9.9' }),
    );
    expect(out).toEqual({
      statusCode: 200,
      doubled: 42,
      nodeVersion: 'v24.9.9',
    });
  });
});

describe('services/lambda/invoke — cliInvokeArgs (#136 regression lock)', () => {
  const OUT = '/some/tmp/out.json';

  it('builds the exact `aws lambda invoke` argv in order', () => {
    expect(cliInvokeArgs('compat-lambda-doubler', { n: 21 }, OUT)).toEqual([
      'lambda',
      'invoke',
      '--function-name',
      'compat-lambda-doubler',
      '--payload',
      '{"n":21}',
      '--cli-binary-format',
      'raw-in-base64-out',
      OUT,
    ]);
  });

  // #136 REGRESSION LOCK: the `--payload` value MUST be RAW JSON, and it MUST be
  // paired with `--cli-binary-format raw-in-base64-out`. The original #136 sketch
  // passed base64 (`Buffer.from(json).toString('base64')`) under
  // `raw-in-base64-out`, which double-encodes: the CLI forwards the base64 TEXT
  // verbatim, the handler JSON.parses that text, `n` is NaN, and a bogus 400 is
  // returned. This test fails if the payload is ever base64-encoded again OR if
  // the raw-in-base64-out pairing is dropped.
  it('passes RAW JSON as --payload, never base64, paired with raw-in-base64-out', () => {
    const args = cliInvokeArgs('fn', { n: 21 }, OUT);
    const payloadIdx = args.indexOf('--payload');
    const payload = args[payloadIdx + 1];

    // The payload is the raw JSON the handler can JSON.parse to the input object.
    expect(payload).toBe('{"n":21}');
    expect(JSON.parse(payload)).toEqual({ n: 21 });

    // And it is explicitly NOT the base64 double-encoding the #136 bug shipped.
    const base64 = Buffer.from(JSON.stringify({ n: 21 })).toString('base64');
    expect(payload).not.toBe(base64);

    // The raw-in-base64-out flag must be present so the CLI treats blob INPUT as
    // raw — dropping it re-introduces the base64-default mismatch.
    const fmtIdx = args.indexOf('--cli-binary-format');
    expect(fmtIdx).toBeGreaterThan(-1);
    expect(args[fmtIdx + 1]).toBe('raw-in-base64-out');
  });

  it('interpolates the function name and out-file positionally', () => {
    const args = cliInvokeArgs('another-fn', { n: 'abc' }, '/x/y.json');
    expect(args[args.indexOf('--function-name') + 1]).toBe('another-fn');
    expect(args[args.length - 1]).toBe('/x/y.json');
    expect(args[args.indexOf('--payload') + 1]).toBe('{"n":"abc"}');
  });
});
