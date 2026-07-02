import { checkSdk } from '../../../services/lambda/checks.sdk';
import { checkCli } from '../../../services/lambda/checks.cli';
import { cdkLambda } from '../../../services/lambda/iac/cdk/deploy';
import type { LambdaContract } from '../../../services/lambda/contract';

/**
 * Lambda vertical of the MiniStack compat harness (epic #117, sub-issue B /
 * #136): the reference `describe.each(adapters) × it.each(oracles)` matrix.
 *
 * The oracles (checkSdk / checkCli) are defined ONCE in services/lambda/ and
 * are provisioner-blind — they take only a LambdaContract. Each IaC-tool
 * adapter is one entry in `adapters`; today only CDK exists (it short-circuits
 * to the already-deployed `cdk-doubler`). Terraform/CloudFormation adapters
 * arrive in later sub-issues as one extra array entry each, with NO change to
 * the oracles.
 *
 * INTEGRATION tier: assumes a live MiniStack with `cdk deploy` already run
 * (mirror the CI ordering) — it does NOT run in the unit tier and cannot run
 * without an emulator. It emits named JUnit cases to reports/junit/integration.xml:
 *   lambda provisioned via cdk › passes the sdk oracle
 *   lambda provisioned via cdk › passes the cli oracle
 * (each oracle asserts both the happy path and the handled-400 case, so the
 * four acceptance cases — cdk × {sdk,cli} × {happy,400} — are all exercised).
 */
const adapters = [cdkLambda /*, terraformLambda, cfnLambda — added later */];
const oracles = { sdk: checkSdk, cli: checkCli };

describe.each(adapters)('lambda provisioned via $name', (adapter) => {
  let c: LambdaContract;

  beforeAll(async () => {
    c = await adapter.deploy();
  }, 120_000);

  afterAll(async () => {
    await adapter.teardown?.();
  });

  it.each(Object.entries(oracles))('passes the %s oracle', (_name, oracle) =>
    oracle(c),
  );
});
