import { checkSdk } from '../../../services/s3/checks.sdk';
import { checkCli } from '../../../services/s3/checks.cli';
import { cdkS3 } from '../../../services/s3/iac/cdk/deploy';
import type { S3Contract } from '../../../services/s3/contract';

/**
 * S3 vertical of the MiniStack compat harness (epic #117, #139,
 * self-provisioning #147): the `describe.each(adapters) × it.each(oracles)`
 * matrix, a structural clone of `test/integration/services/lambda.test.ts`.
 *
 * The oracles (checkSdk / checkCli) are defined ONCE in services/s3/ and are
 * provisioner-blind — they take only an S3Contract. Each IaC-tool adapter is one
 * entry in `adapters`; today only CDK exists. The CDK adapter SELF-PROVISIONS its
 * own `CompatS3Stack` (`compat-s3-bucket`) in `beforeAll` — verify-or-provision,
 * decoupled from the demo stack `lib/ministack-stack.ts` (#147). It does NOT
 * short-circuit to the demo-deployed `cdk-demo-bucket`. Terraform/CloudFormation
 * adapters arrive in later sub-issues as one extra array entry each, with NO
 * change to the oracles.
 *
 * INTEGRATION tier: needs a live MiniStack but NOT a prior `cdk deploy` — the
 * adapter provisions its own stack on demand. It does NOT run in the unit tier
 * and cannot run without an emulator. It emits named JUnit cases to
 * reports/junit/integration.xml:
 *   s3 provisioned via cdk › passes the sdk oracle
 *   s3 provisioned via cdk › passes the cli oracle
 * (each oracle does a full PUT/GET object round-trip against the deployed
 * bucket).
 *
 * The `beforeAll` timeout covers a COLD `cdk bootstrap` + `cdk deploy` of the
 * compat stack on a fresh MiniStack; 300_000ms gives ample headroom over the
 * default 120_000. The verify fast-path (bucket already up) short-circuits in
 * well under a second, so warm re-runs never approach the limit.
 */
const adapters = [cdkS3 /*, terraformS3, cfnS3 — added later */];
const oracles = { sdk: checkSdk, cli: checkCli };

describe.each(adapters)('s3 provisioned via $name', (adapter) => {
  let c: S3Contract;

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
