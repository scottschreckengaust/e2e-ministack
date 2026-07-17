import { checkSdk } from '../../../services/dynamodb/checks.sdk';
import { checkCli } from '../../../services/dynamodb/checks.cli';
import { cdkDynamo } from '../../../services/dynamodb/iac/cdk/deploy';
import type { DynamoContract } from '../../../services/dynamodb/contract';

/**
 * DynamoDB vertical of the MiniStack compat harness (epic #117, #140,
 * self-provisioning #147): the `describe.each(adapters) × it.each(oracles)`
 * matrix, a structural clone of `test/integration/services/s3.test.ts` and
 * `lambda.test.ts`.
 *
 * The oracles (checkSdk / checkCli) are defined ONCE in services/dynamodb/ and
 * are provisioner-blind — they take only a DynamoContract. Each IaC-tool adapter
 * is one entry in `adapters`; today only CDK exists. The CDK adapter
 * SELF-PROVISIONS its own `CompatDynamoStack` (`compat-dynamo-table`) in
 * `beforeAll` — verify-or-provision, decoupled from the demo stack
 * `lib/ministack-stack.ts` (#147). Terraform/CloudFormation adapters arrive in
 * later sub-issues as one extra array entry each, with NO change to the oracles.
 *
 * PROVENANCE PROOF (mirrors #175): the adapter's `deploy()` no longer trusts a
 * bare verify short-circuit — after both the fast-path skip AND a fresh provision
 * it reads the table back via `DescribeTable` and asserts the distinctive
 * partition-key marker (`COMPAT_DYNAMO_PARTITION_KEY`) that ONLY `HardenedTable`/
 * `CompatDynamoStack` sets. So `beforeAll` here THROWS if the addressed
 * `compat-dynamo-table` is a stale or foreign table of the same name rather than
 * one this stack provisioned — the oracle can no longer green against a resource
 * the harness didn't create. (The marker + the read-back's pure predicate are
 * unit-tested in test/unit/services/dynamodb-construct.test.ts,
 * dynamodb-compat-stack.test.ts, and dynamodb-health.test.ts; the live read-back
 * itself runs only here in the integration tier.)
 *
 * INTEGRATION tier: needs a live MiniStack but NOT a prior `cdk deploy` — the
 * adapter provisions its own stack on demand. It does NOT run in the unit tier
 * and cannot run without an emulator. It emits named JUnit cases to
 * reports/junit/integration.xml:
 *   dynamodb provisioned via cdk › passes the sdk oracle
 *   dynamodb provisioned via cdk › passes the cli oracle
 * (each oracle does a full PutItem/GetItem round-trip against the deployed
 * table).
 *
 * The `beforeAll` timeout covers a COLD `cdk bootstrap` + `cdk deploy` of the
 * compat stack on a fresh MiniStack; 300_000ms gives ample headroom over the
 * default 120_000. The verify fast-path (table already up) short-circuits in
 * well under a second, so warm re-runs never approach the limit.
 */
const adapters = [cdkDynamo /*, terraformDynamo, cfnDynamo — added later */];
const oracles = { sdk: checkSdk, cli: checkCli };

describe.each(adapters)('dynamodb provisioned via $name', (adapter) => {
  let c: DynamoContract;

  beforeAll(async () => {
    c = await adapter.deploy();
  }, 300_000);

  afterAll(async () => {
    await adapter.teardown?.();
  });

  it.each(Object.entries(oracles))('passes the %s oracle', (_name, oracle) =>
    oracle(c),
  );
});
