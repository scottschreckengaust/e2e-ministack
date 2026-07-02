import { readFileSync } from 'node:fs';
import * as path from 'node:path';
import Ajv, { type ValidateFunction } from 'ajv';

// Unit-tier schema gate for the MiniStack compatibility registries
// (epic #117, sub-issue A / #135). Mirrors test/unit/license-verdict.test.ts:
// a pure-logic unit test (no emulator) that validates committed JSON against
// its committed JSON Schema with ajv, so a malformed/half-authored registry
// row fails the fast gate and the source-of-truth registry can't rot.
//
// ajv (MIT, on the repo's permissive allow-list) is a direct devDependency;
// it resolves to draft-07-capable ajv v6, which is why the schemas declare
// $schema draft-07. JSON is read via fs.readFileSync + JSON.parse rather than
// `import` so no tsconfig resolveJsonModule change is needed.

const REGISTRY_DIR = path.resolve(__dirname, '../../services/_registry');

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(path.join(REGISTRY_DIR, file), 'utf8'));
}

// ajv v6 default constructor targets draft-07 (matches the schema $schema).
const ajv = new Ajv({ allErrors: true });

const supportSchema = readJson('ministack-support.schema.json') as object;
const provisioningSchema = readJson('provisioning.schema.json') as object;
const supportData = readJson('ministack-support.json') as {
  services: Array<{ service: string; status: string }>;
};
const provisioningData = readJson('provisioning.json') as {
  results: unknown[];
};

const validateSupport: ValidateFunction = ajv.compile(supportSchema);
const validateProvisioning: ValidateFunction = ajv.compile(provisioningSchema);

// The full Axis-1 target scope from epic #117. ministack-support.json MUST
// carry exactly one row per service (breadth authored up front).
const EXPECTED_SERVICES = [
  'lambda',
  'stepfunctions',
  's3',
  'dynamodb',
  'sqs',
  'sns',
  'eventbridge',
  'apigateway',
  'rds-postgres',
  'cloudfront',
  'route53',
  'ecs',
  'eks',
  'dsql',
  'agentcore',
];

const VALID_STATUSES = [
  'supported',
  'partial',
  'unsupported',
  'upstream-tracked',
];

describe('MiniStack compatibility registries — unit schema gate', () => {
  describe('ministack-support.json (Axis 1 — API breadth)', () => {
    it('validates against its schema', () => {
      const ok = validateSupport(supportData);
      // Surface ajv errors in the failure message if it ever regresses.
      expect(validateSupport.errors ?? []).toEqual([]);
      expect(ok).toBe(true);
    });

    it('has a row for every one of the 15 target services (no more, no less)', () => {
      const seen = supportData.services.map((r) => r.service);
      expect([...seen].sort()).toEqual([...EXPECTED_SERVICES].sort());
      expect(seen).toHaveLength(EXPECTED_SERVICES.length);
      // No duplicate service keys.
      expect(new Set(seen).size).toBe(seen.length);
    });

    it('uses only allow-listed status values', () => {
      for (const row of supportData.services) {
        expect(VALID_STATUSES).toContain(row.status);
      }
    });

    it('enforces the status enum (rejects an out-of-enum value)', () => {
      const badRow = {
        service: 'lambda',
        status: 'kinda-works', // not in the enum
        evidence: 'x',
        evidenceUrl: 'https://example.com',
        ministackRef: null,
      };
      expect(validateSupport({ services: [badRow] })).toBe(false);
    });

    it('rejects a malformed row (missing required field)', () => {
      const badRow = {
        service: 'lambda',
        status: 'supported',
        // evidence omitted
        evidenceUrl: 'https://example.com',
        ministackRef: null,
      };
      expect(validateSupport({ services: [badRow] })).toBe(false);
    });

    it('rejects an unknown extra property (additionalProperties: false)', () => {
      const badRow = {
        service: 'lambda',
        status: 'supported',
        evidence: 'x',
        evidenceUrl: 'https://example.com',
        ministackRef: null,
        surprise: true,
      };
      expect(validateSupport({ services: [badRow] })).toBe(false);
    });

    it('rejects a malformed ministackRef (must be owner/repo#N or null)', () => {
      const badRow = {
        service: 'agentcore',
        status: 'upstream-tracked',
        evidence: 'x',
        evidenceUrl: 'https://example.com',
        ministackRef: 'not-a-ref',
      };
      expect(validateSupport({ services: [badRow] })).toBe(false);
    });
  });

  describe('provisioning.json (Axis 2 — depth)', () => {
    it('validates against its schema', () => {
      const ok = validateProvisioning(provisioningData);
      expect(validateProvisioning.errors ?? []).toEqual([]);
      expect(ok).toBe(true);
    });

    it('carries the lambda/cdk vertical row (first appended by #136)', () => {
      // #135 authored this registry empty; the first vertical (#136) appends
      // the lambda × AWS::Lambda::Function × cdk row, stamped with the pinned
      // MiniStack digest. Assert it is present and green so the rot-guard also
      // catches a later accidental deletion/verdict regression of it.
      const rows = provisioningData.results as Array<{
        service: string;
        resource: string;
        iac: string;
        deploy: string;
        oracles: { sdk: string; cli: string };
        lastVerifiedDigest: string;
      }>;
      const lambdaCdk = rows.find(
        (r) => r.service === 'lambda' && r.iac === 'cdk',
      );
      expect(lambdaCdk).toBeDefined();
      expect(lambdaCdk!.resource).toBe('AWS::Lambda::Function');
      expect(lambdaCdk!.deploy).toBe('pass');
      expect(lambdaCdk!.oracles).toEqual({ sdk: 'pass', cli: 'pass' });
      expect(lambdaCdk!.lastVerifiedDigest).toMatch(/^sha256:[0-9a-f]{64}$/);
    });

    it('enforces the deploy/oracles verdict enum (rejects a bad verdict)', () => {
      const badRow = {
        service: 'lambda',
        resource: 'AWS::Lambda::Function',
        iac: 'cdk',
        deploy: 'maybe', // not in pass|fail|skipped
        oracles: { sdk: 'pass', cli: 'pass' },
        lastVerifiedDigest:
          'sha256:c5ce466eb2e73b5f3af86a5a1aea780c1e8fcf8f04ec0e2042a5cf759d6dcdd3',
        notes: '',
      };
      expect(validateProvisioning({ results: [badRow] })).toBe(false);
    });

    it('accepts a well-formed provisioning row shape', () => {
      const goodRow = {
        service: 'lambda',
        resource: 'AWS::Lambda::Function',
        iac: 'cdk',
        deploy: 'pass',
        oracles: { sdk: 'pass', cli: 'pass' },
        lastVerifiedDigest:
          'sha256:c5ce466eb2e73b5f3af86a5a1aea780c1e8fcf8f04ec0e2042a5cf759d6dcdd3',
        notes: '',
      };
      expect(validateProvisioning({ results: [goodRow] })).toBe(true);
    });
  });
});
