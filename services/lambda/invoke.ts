/**
 * The PURE invoke logic for the Lambda vertical's behavioral oracles (epic
 * #117, #151 / #144). This is the fast-tier safety net: the payload-encoding and
 * response-parsing that both `checks.sdk.ts` (SDK) and `checks.cli.ts` (CLI)
 * depend on, extracted out of those coverage-EXCLUDED I/O shells into a
 * coverage-INCLUDED module so it is unit-testable WITHOUT a live MiniStack.
 *
 * Why extract (the harness-wide policy — see `services/README.md` § Coverage):
 * the oracles' real work is live I/O the unit tier can't instrument
 * (`LambdaClient.send(Invoke)`, `execFile('aws', …)`), so they stay excluded.
 * But the #136 bug — AWS CLI v2's `--payload` base64 default double-encoding
 * under `--cli-binary-format raw-in-base64-out` — lived in PURE payload logic
 * that an emulator-free unit test can pin. **Extract the pure logic to a gated
 * module; keep only genuine I/O in the excluded shell; never mock the
 * emulator/CLI/SDK to chase coverage.** This mirrors the `_harness/*.ts` /
 * `health.ts` precedent (PR #148).
 *
 * PER-VERTICAL: this classifies the doubler function's invoke payload/response;
 * S3/DynamoDB verticals extract their own pure seams the same way. Pure
 * functions over explicit args (no `process.env` reads, no I/O), so every branch
 * is exercised deterministically and the module is held at the repo's 100% gate.
 */

/** The response envelope the `cdk-doubler` handler returns for both paths. */
export interface InvokeResult {
  statusCode: number;
  doubled?: number;
  nodeVersion?: string;
}

/**
 * The SDK `InvokeCommand` `Payload`: the input object as a UTF-8 JSON byte
 * buffer. `@aws-sdk/client-lambda` accepts a `Uint8Array` here; `Buffer` (a
 * `Uint8Array` subclass) satisfies it. Kept as pure serialization so a unit test
 * can prove the bytes on the wire are exactly `JSON.stringify(input)` — no
 * base64, no coercion.
 */
export function buildSdkPayload(input: unknown): Uint8Array {
  return Buffer.from(JSON.stringify(input));
}

/**
 * Decode an invoke response `Payload` (SDK) or a CLI invoke output-file body
 * into the typed {@link InvokeResult}. The SDK hands back a `Uint8Array`; the
 * CLI hands back a UTF-8 string from the temp file. `Buffer.from(...)` accepts
 * both a string (identity UTF-8 round-trip) and a `Uint8Array` (byte decode), so
 * one branch-free decode covers both callers — no `typeof` branch to leave an
 * equivalent mutant, since `Buffer.from(string).toString('utf8')` is lossless.
 */
export function parseInvokePayload(payload: Uint8Array | string): InvokeResult {
  const text = Buffer.from(payload).toString('utf8');
  return JSON.parse(text) as InvokeResult;
}

/**
 * Build the `aws lambda invoke` argv for {@link checkCli}'s `execFile` call —
 * the EXACT command a human pastes into AWS CloudShell, and the seam the #136
 * double-encoding bug lived in.
 *
 * #136: AWS CLI v2 changed the `--payload` blob default to expect BASE64 (v1
 * accepted raw text). Passing `--cli-binary-format raw-in-base64-out` flips blob
 * INPUT back to RAW, so `--payload` must carry RAW JSON — the two settings have
 * to be consistent. If instead a base64 string is passed under
 * `raw-in-base64-out` the CLI forwards the base64 TEXT verbatim, the handler
 * `JSON.parse`s that text, `n` comes back NaN, and a bogus 400 is returned.
 * Raw JSON + raw-in-base64-out is also the human-friendly form the oracle proves
 * (exactly what you paste into CloudShell). The out-file is the last positional
 * argument. `functionName` is our own contract value and is passed as a single
 * argv element (execFile, never a shell), so there is no injection surface.
 */
export function cliInvokeArgs(
  functionName: string,
  input: unknown,
  outFile: string,
): string[] {
  return [
    'lambda',
    'invoke',
    '--function-name',
    functionName,
    '--payload',
    // RAW JSON (paired with raw-in-base64-out below) — NOT base64 (#136).
    JSON.stringify(input),
    '--cli-binary-format',
    'raw-in-base64-out',
    outFile,
  ];
}
