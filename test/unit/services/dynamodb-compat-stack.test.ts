import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import { AwsSolutionsChecks } from 'cdk-nag';
import {
  CompatDynamoStack,
  COMPAT_DYNAMO_TABLE_NAME,
} from '../../../services/dynamodb/iac/cdk/stack';
import {
  COMPAT_DYNAMO_PARTITION_KEY,
  COMPAT_DYNAMO_PROVENANCE_TAG,
} from '../../../services/dynamodb/iac/cdk/construct';
import { buildCompatApp } from '../../../services/dynamodb/iac/cdk/app';
import { MINISTACK_ENV } from '../../../lib/env';

// Pure-synth unit test for the DynamoDB/CDK vertical's self-provisioned compat
// stack + app entrypoint (epic #117, #140). Mirrors
// test/unit/services/s3-compat-stack.test.ts: synthesize to CloudFormation and
// assert against the template — no AWS, no MiniStack, no Docker.
//
// stack.ts and app.ts are under services/ but are NOT checks.*.ts, deploy.ts,
// or *.test.ts, so jest.config.js holds them at the repo's 100% coverage gate.
// This test exercises them in full so they stay there. The adapter's
// integration-tier provisioner (iac/cdk/deploy.ts) is coverage-excluded by the
// path convention and proven instead by the CI Integration job.
//
// Every CDK-matcher `it()` also carries a literal expect(...) (SonarQube S2699 —
// CDK matchers are not counted as assertions).
describe('CompatDynamoStack — self-provisioned compat stack', () => {
  function synth(): Template {
    const app = new cdk.App();
    const stack = new CompatDynamoStack(app, 'CompatDynamoStack');
    return Template.fromStack(stack);
  }

  const template = synth();

  it('names the table compat-dynamo-table', () => {
    const names = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    ).map((t) => t.Properties.TableName);
    expect(names).toEqual([COMPAT_DYNAMO_TABLE_NAME]);
  });

  it('uses the compat-* naming convention (distinct, decoupled from any demo table)', () => {
    // The whole point of the distinct compat-* name is that MiniStack shares one
    // global namespace: a distinct name makes the harness independent of whether
    // any other stack is deployed. Lock the convention so a future edit that
    // "simplifies" back to a demo-style name fails here rather than in a
    // confusing MiniStack collision. Mirrors the sibling verticals' guard.
    expect(COMPAT_DYNAMO_TABLE_NAME).toBe('compat-dynamo-table');
    expect(COMPAT_DYNAMO_TABLE_NAME.startsWith('compat-')).toBe(true);
  });

  it('carries the hardened table shape (PITR + CMK encryption + provenance markers)', () => {
    template.resourceCountIs('AWS::DynamoDB::Table', 1);
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      SSESpecification: Match.objectLike({ SSEEnabled: true }),
      KeySchema: Match.arrayWith([
        Match.objectLike({
          AttributeName: COMPAT_DYNAMO_PARTITION_KEY,
          KeyType: 'HASH',
        }),
      ]),
    });
    // Companion literal assertions (SonarQube S2699): exactly one table, PITR on,
    // and the provenance partition key present.
    const tables = template.findResources('AWS::DynamoDB::Table');
    expect(Object.keys(tables)).toHaveLength(1);
    const table = Object.values(tables)[0];
    expect(
      table.Properties.PointInTimeRecoverySpecification
        .PointInTimeRecoveryEnabled,
    ).toBe(true);
    const hashKey = table.Properties.KeySchema.find(
      (k: { KeyType: string }) => k.KeyType === 'HASH',
    );
    expect(hashKey.AttributeName).toBe(COMPAT_DYNAMO_PARTITION_KEY);
  });

  it('stamps the provenance partition key + tag the integration read-back checks', () => {
    // The integration adapter (iac/cdk/deploy.ts) reads the table back via
    // DescribeTable after deploy — on the verify fast-path AND after a fresh
    // provision — and requires this exact partition-key marker. A stale/foreign
    // compat-dynamo-table from an unrelated source lacks it, so the adapter fails
    // loudly instead of letting the oracle green against a table this stack never
    // provisioned. Lock the markers into the synthesized template so they can
    // never silently drift away from what deploy.ts asserts.
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      KeySchema: Match.arrayWith([
        Match.objectLike({
          AttributeName: COMPAT_DYNAMO_PARTITION_KEY,
          KeyType: 'HASH',
        }),
      ]),
      Tags: Match.arrayWith([
        Match.objectLike({
          Key: COMPAT_DYNAMO_PROVENANCE_TAG.key,
          Value: COMPAT_DYNAMO_PROVENANCE_TAG.value,
        }),
      ]),
    });
    const table = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    )[0];
    const tags = table.Properties.Tags as Array<{
      Key: string;
      Value: string;
    }>;
    expect(tags).toContainEqual({
      Key: COMPAT_DYNAMO_PROVENANCE_TAG.key,
      Value: COMPAT_DYNAMO_PROVENANCE_TAG.value,
    });
  });

  it('pins the deploy target to the MiniStack account/region unconditionally', () => {
    const app = new cdk.App();
    const stack = new CompatDynamoStack(app, 'CompatDynamoStack');
    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });
});

describe('CompatDynamoStack — cdk-nag (AwsSolutions) fast-tier gate', () => {
  it('synthesizes with zero unsuppressed AwsSolutions findings', () => {
    // Parity with test/unit/services/s3-compat-stack.test.ts. bin/app.ts and the
    // compat app.ts attach the AwsSolutions pack via the cdk-nag v3
    // policy-validation API (Validations.of(app).addPlugins(...)), but that gate
    // only fires inside the CDK CLI's `cdk synth`. We drive the SAME pack class
    // directly via its documented `validateScope(stack)` entry point so a nag
    // regression in the compat stack fails fast in the unit tier, not only in CI
    // synth.
    const app = new cdk.App();
    const stack = new CompatDynamoStack(app, 'NagCompatDynamoStack');
    app.synth();

    const report = new AwsSolutionsChecks(stack, {
      verbose: true,
    }).validateScope(stack);
    const findings = report.violations.map(
      (v) => `${v.ruleName}: ${v.description}`,
    );
    expect(findings).toEqual([]);
    expect(report.success).toBe(true);
  });
});

describe('buildCompatApp — per-vertical CDK app entrypoint', () => {
  it('instantiates the CompatDynamoStack pinned to the MiniStack env', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatDynamoStack') as cdk.Stack;

    expect(stack.account).toBe(MINISTACK_ENV.account);
    expect(stack.region).toBe(MINISTACK_ENV.region);
  });

  it('synthesizes the compat-dynamo-table through the app', () => {
    const app = buildCompatApp();
    const stack = app.node.findChild('CompatDynamoStack') as cdk.Stack;
    const template = Template.fromStack(stack);
    const names = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    ).map((t) => t.Properties.TableName);
    expect(names).toContain(COMPAT_DYNAMO_TABLE_NAME);
  });

  it('attaches the cdk-nag AwsSolutions pack to the app (so `cdk synth` gates)', () => {
    // The cdk-nag "zero findings" test above drives the pack class DIRECTLY, so
    // it passes even if app.ts forgot to register the pack — meaning the one line
    // that makes the CLI's `cdk synth` actually enforce cdk-nag on the compat
    // stack (Validations.of(app).addPlugins(new AwsSolutionsChecks(...))) was
    // executed-but-not-ASSERTED: deleting it kept every test green at 100%
    // coverage. Assert the effect here — the app must carry the pack as a
    // registered policy-validation plugin. Mirrors the sibling verticals' test.
    const app = buildCompatApp();
    const pluginNames = app.policyValidationBeta1.map((p) => p.name);
    expect(pluginNames).toContain('AwsSolutions');
  });
});
