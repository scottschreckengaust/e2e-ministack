import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import Ajv, { type ValidateFunction } from 'ajv';
import draft04 from 'ajv/lib/refs/json-schema-draft-04.json';
import {
  injectSuppressions,
  type SarifLogLike,
} from '../../.github/scripts/vex-to-sarif-suppressions';

// Schema gate for the vex-to-sarif-suppressions OUTPUT (#187, fast-follow of
// #181/#186). The behavioural unit tests assert against our hand-written
// `SarifLogLike` types; this test asserts the injector's output is valid
// *SARIF 2.1.0* against the vendored OASIS schema — a different, stronger
// contract (it catches "valid TS shape, invalid SARIF", e.g. a suppression
// missing its required `kind`).
//
// This is defense-in-depth, not a correctness gap: `github/codeql-action/
// upload-sarif` already validates our (non-CodeQL) grype SARIF client-side
// against the same OASIS schema and hard-fails the job. Keeping the check here
// (a) fails the injector's own test with a local, blame-localised message and
// (b) survives a future change that weakens the upload backstop. Mirrors the
// existing `registry.test.ts` "validate committed JSON against its committed
// schema with ajv" pattern; adds NO new dependency (ajv v6 is already a direct
// devDependency, MIT, on the permissive allow-list).
//
// The vendored schema is the OASIS errata01 canonical `sarif-schema-2.1.0.json`
// (declares draft-04 — verified: GitHub's bundled copy shares 51/52 identical
// definitions, incl. `suppression` requiring `kind`; the only delta is GitHub
// RELAXING the `region` constraint, so passing OASIS ⇒ passing GitHub ingest
// for the field we emit). See #187 for the equivalence evidence.

const SCHEMA_PATH = path.resolve(
  __dirname,
  '../fixtures/sarif-schema-2.1.0.json',
);
const sarifSchema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf8')) as object;

// The SARIF schema declares draft-04; ajv v6 bundles that meta-schema but does
// not enable it by default. Register it and select the draft-04 schema id.
// (No `allErrors` — the first error is enough to diagnose a regression, and it
// avoids the unbounded-error-allocation pattern semgrep flags.)
const ajv = new Ajv({ schemaId: 'auto' });
ajv.addMetaSchema(draft04);
const validateSarif: ValidateFunction = ajv.compile(sarifSchema);

/** Assert a document is valid SARIF 2.1.0, surfacing ajv errors on failure. */
function expectValidSarif(doc: unknown): void {
  const ok = validateSarif(doc);
  if (!ok) {
    throw new Error(
      `output is not valid SARIF 2.1.0:\n${JSON.stringify(validateSarif.errors, null, 2)}`,
    );
  }
  expect(ok).toBe(true);
}

// A realistic grype image-CVE SARIF: package-level finding with a synthetic
// (1,1) region, matching the shape grype emits for image CVEs (observed on the
// real repo alerts). One CVE that a VEX record covers, one that it doesn't.
function grypeImageSarif(): SarifLogLike {
  const rule = (id: string) => ({
    id,
    name: id,
    shortDescription: { text: `Vulnerability ${id}` },
    properties: { 'security-severity': '7.5', tags: ['security'] },
  });
  const result = (ruleId: string, ruleIndex: number) => ({
    ruleId,
    ruleIndex,
    level: 'error',
    message: { text: `A vulnerability in package for ${ruleId}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: 'image//usr/lib/x' },
          region: { startLine: 1, endLine: 1, startColumn: 1, endColumn: 1 },
        },
      },
    ],
  });
  return {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Grype',
            rules: [rule('CVE-2026-11822-libsqlite3-0'), rule('CVE-2099-1-x')],
          },
        },
        results: [
          result('CVE-2026-11822-libsqlite3-0', 0),
          result('CVE-2099-1-x', 1),
        ],
      },
    ],
  } as SarifLogLike;
}

const VEX = {
  statements: [
    {
      vulnerability: { name: 'CVE-2026-11822' },
      status: 'not_affected',
      justification: 'vulnerable_code_cannot_be_controlled_by_adversary',
      impact_statement: 'Accepted risk: local-only CI emulator.',
    },
  ],
};

describe('vex-to-sarif-suppressions — output is valid SARIF 2.1.0 (schema gate #187)', () => {
  it('the vendored schema is the OASIS draft-04 canonical and requires suppression.kind', () => {
    const s = sarifSchema as {
      $schema: string;
      definitions: { suppression: { required: string[] } };
    };
    expect(s.$schema).toBe('http://json-schema.org/draft-04/schema#');
    // The field our injector sets is schema-required — so an omission is caught.
    expect(s.definitions.suppression.required).toContain('kind');
  });

  it('injected output (covered + uncovered results) validates against the schema', () => {
    const { sarif } = injectSuppressions(grypeImageSarif(), [VEX]);
    expectValidSarif(sarif);
  });

  it('the covered result carries a schema-valid external suppression', () => {
    const { sarif } = injectSuppressions(grypeImageSarif(), [VEX]);
    const results = (
      sarif.runs as Array<{ results: Array<Record<string, unknown>> }>
    )[0].results;
    const covered = results.find(
      (r) => r.ruleId === 'CVE-2026-11822-libsqlite3-0',
    )!;
    const supp = covered.suppressions as Array<{ kind: string }>;
    expect(supp[0].kind).toBe('external'); // schema enum: inSource | external
    expectValidSarif(sarif);
  });

  it('empty-suppressions (uncovered) output is still valid SARIF', () => {
    // No VEX docs → every result gets `suppressions: []`; must stay schema-valid.
    const { sarif } = injectSuppressions(grypeImageSarif(), []);
    expectValidSarif(sarif);
  });

  it('degenerate input still yields schema-valid SARIF (totality meets schema)', () => {
    for (const bad of [{}, { runs: 'x' }, null, [1, 2, 3]]) {
      const { sarif } = injectSuppressions(bad as unknown as SarifLogLike, [
        VEX,
      ]);
      expectValidSarif(sarif);
    }
  });

  it('a deliberately malformed suppression (missing kind) is REJECTED by the gate', () => {
    // Proves the gate has teeth: hand-build an invalid SARIF and confirm the
    // validator fails it (so a future injector regression that drops `kind`
    // would be caught here, not just downstream at upload).
    const bad = {
      version: '2.1.0',
      runs: [
        {
          tool: { driver: { name: 'Grype' } },
          results: [
            {
              message: { text: 'x' },
              locations: [
                { physicalLocation: { artifactLocation: { uri: 'a' } } },
              ],
              suppressions: [{ justification: 'no kind here' }], // missing required `kind`
            },
          ],
        },
      ],
    };
    expect(validateSarif(bad)).toBe(false);
  });
});
