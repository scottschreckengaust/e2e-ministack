import * as cdk from 'aws-cdk-lib';
import { Template, Match } from 'aws-cdk-lib/assertions';
import {
  HardenedTable,
  COMPAT_DYNAMO_PARTITION_KEY,
  COMPAT_DYNAMO_PROVENANCE_TAG,
} from '../../../services/dynamodb/iac/cdk/construct';

// Pure-synth unit test for the reusable DynamoDB construct fragment shipped by
// the compat harness (epic #117, #140). Mirrors
// test/unit/services/lambda-construct.test.ts and s3-construct.test.ts:
// synthesize a throwaway stack containing only the construct and assert against
// the resulting CloudFormation template. No AWS, no MiniStack, no Docker.
//
// The construct is under iac/** but NOT named deploy.ts, so it is coverage
// GATED at 100%; this test holds it there.
//
// Each `it()` that uses a CDK Template matcher (hasResourceProperties /
// resourceCountIs) ALSO carries a literal expect(...): SonarQube (S2699) does
// not count CDK matchers as assertions, so a matcher-only test would be flagged
// as "no assertions". Mirrors the paired-assertion idiom in s3-construct.test.ts.
function synth(): Template {
  const app = new cdk.App();
  const stack = new cdk.Stack(app, 'ConstructTestStack');
  new HardenedTable(stack, 'Table');
  return Template.fromStack(stack);
}

describe('HardenedTable construct — fine-grained synth assertions', () => {
  const template = synth();

  it('provisions exactly one DynamoDB table', () => {
    template.resourceCountIs('AWS::DynamoDB::Table', 1);
    expect(
      Object.keys(template.findResources('AWS::DynamoDB::Table')),
    ).toHaveLength(1);
  });

  it('keys the table on the distinctive provenance partition key (STRING HASH)', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      KeySchema: Match.arrayWith([
        Match.objectLike({
          AttributeName: COMPAT_DYNAMO_PARTITION_KEY,
          KeyType: 'HASH',
        }),
      ]),
      AttributeDefinitions: Match.arrayWith([
        Match.objectLike({
          AttributeName: COMPAT_DYNAMO_PARTITION_KEY,
          AttributeType: 'S',
        }),
      ]),
    });
    // Companion literal assertion (SonarQube S2699). The synthesized HASH key is
    // exactly the marker name the deploy.ts read-back keys on.
    const table = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    )[0];
    const hashKey = table.Properties.KeySchema.find(
      (k: { KeyType: string }) => k.KeyType === 'HASH',
    );
    expect(hashKey.AttributeName).toBe(COMPAT_DYNAMO_PARTITION_KEY);
  });

  it('enables point-in-time recovery (AwsSolutions-DDB3)', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      PointInTimeRecoverySpecification: {
        PointInTimeRecoveryEnabled: true,
      },
    });
    const table = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    )[0];
    expect(
      table.Properties.PointInTimeRecoverySpecification
        .PointInTimeRecoveryEnabled,
    ).toBe(true);
  });

  it('uses PAY_PER_REQUEST billing (no provisioned capacity to autoscale)', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      BillingMode: 'PAY_PER_REQUEST',
    });
    const table = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    )[0];
    expect(table.Properties.BillingMode).toBe('PAY_PER_REQUEST');
    // PAY_PER_REQUEST tables carry no ProvisionedThroughput block.
    expect(table.Properties.ProvisionedThroughput).toBeUndefined();
  });

  it('encrypts the table with a customer-managed rotated CMK', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      SSESpecification: Match.objectLike({
        SSEEnabled: true,
        KMSMasterKeyId: Match.anyValue(),
      }),
    });
    const keys = template.findResources('AWS::KMS::Key');
    const rotated = Object.values(keys).filter(
      (k) => k.Properties.EnableKeyRotation === true,
    );
    // Exactly one CMK for the table, rotation-enabled.
    expect(rotated).toHaveLength(1);
  });

  it('stamps the secondary provenance CDK tag on the table', () => {
    template.hasResourceProperties('AWS::DynamoDB::Table', {
      Tags: Match.arrayWith([
        Match.objectLike({
          Key: COMPAT_DYNAMO_PROVENANCE_TAG.key,
          Value: COMPAT_DYNAMO_PROVENANCE_TAG.value,
        }),
      ]),
    });
    // Companion literal assertion (SonarQube S2699): the tag pair is present.
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

  it('names the table cdk-demo-table by default', () => {
    const names = Object.values(
      template.findResources('AWS::DynamoDB::Table'),
    ).map((t) => t.Properties.TableName);
    expect(names).toEqual(['cdk-demo-table']);
  });

  it('honors an explicit tableName prop', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'NamedStack');
    new HardenedTable(stack, 'Named', { tableName: 'my-table' });
    const named = Template.fromStack(stack);
    const names = Object.values(
      named.findResources('AWS::DynamoDB::Table'),
    ).map((t) => t.Properties.TableName);
    expect(names).toEqual(['my-table']);
  });

  it('exposes the underlying dynamodb.Table so callers can wire it up', () => {
    const app = new cdk.App();
    const stack = new cdk.Stack(app, 'HandleStack');
    const hardened = new HardenedTable(stack, 'Handle');
    // The public `table` handle is a real DynamoDB table construct.
    expect(hardened.table.tableArn).toBeDefined();
    expect(hardened.table.tableName).toBeDefined();
  });
});
