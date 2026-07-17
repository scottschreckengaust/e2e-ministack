import { checkSdk } from '../../../services/lambda/checks.sdk';
import { checkCli } from '../../../services/lambda/checks.cli';
import { cdkLambda } from '../../../services/lambda/iac/cdk/deploy';
import type { LambdaContract } from '../../../services/lambda/contract';

/**
 * Lambda vertical of the MiniStack compat harness (epic #117, sub-issue B /
 * #136, self-provisioning #147): the reference
 * `describe.each(adapters) × it.each(oracles)` matrix.
 *
 * The oracles (checkSdk / checkCli) are defined ONCE in services/lambda/ and
 * are provisioner-blind — they take only a LambdaContract. Each IaC-tool
 * adapter is one entry in `adapters`; today only CDK exists. The CDK adapter
 * now SELF-PROVISIONS its own `CompatLambdaStack` (`compat-lambda-doubler`) in
 * `beforeAll` — verify-or-provision, decoupled from the demo stack
 * `lib/ministack-stack.ts` (#147). It no longer short-circuits to the
 * demo-deployed `cdk-doubler`. Terraform/CloudFormation adapters arrive in
 * later sub-issues as one extra array entry each, with NO change to the oracles.
 *
 * PROVENANCE PROOF (#175): the adapter's `deploy()` no longer trusts a bare
 * verify short-circuit — after both the fast-path skip AND a fresh provision it
 * reads the function back via `GetFunction` and asserts the provenance marker
 * (`DOUBLER_PROVENANCE_DESCRIPTION`) that ONLY `DoublerFunction`/
 * `CompatLambdaStack` stamps. So `beforeAll` here THROWS if the invoked
 * `compat-lambda-doubler` is a stale or foreign function of the same name
 * rather than one this stack provisioned — the oracle can no longer green
 * against a resource the harness didn't create. (The marker + the read-back's
 * pure predicate are unit-tested in test/unit/services/lambda-construct.test.ts,
 * lambda-compat-stack.test.ts, and lambda-health.test.ts; the live read-back
 * itself runs only here in the integration tier.)
 *
 * INTEGRATION tier: needs a live MiniStack but NOT a prior `cdk deploy` — the
 * adapter provisions its own stack on demand. It does NOT run in the unit tier
 * and cannot run without an emulator. It emits named JUnit cases to
 * reports/junit/integration.xml:
 *   lambda provisioned via cdk › passes the sdk oracle
 *   lambda provisioned via cdk › passes the cli oracle
 * (each oracle asserts both the happy path and the handled-400 case, so the
 * four acceptance cases — cdk × {sdk,cli} × {happy,400} — are all exercised).
 *
 * The `beforeAll` timeout covers a COLD `cdk bootstrap` + `cdk deploy` of the
 * compat stack on a fresh MiniStack. Measured end-to-end at ~13s on a fast
 * local host, but CI (ubuntu-latest) and MiniStack's real-container Lambda cold
 * start are much slower, so 300_000ms gives ample headroom over the default
 * 120_000. The verify fast-path (function already up) short-circuits in well
 * under a second, so warm re-runs never approach the limit.
 *
 * The ORACLE cases carry their own {@link ORACLE_TIMEOUT_MS}: `beforeAll` only
 * provisions the function, so the FIRST invocation happens inside the oracle
 * `it` and pays MiniStack's real-container Lambda COLD START. That would
 * otherwise run under jest's default integration `testTimeout` (60_000,
 * jest.config.js) and can flake on a slow CI host; 120_000 gives the cold
 * invoke the same kind of headroom `beforeAll` has for the deploy.
 */
const adapters = [cdkLambda /*, terraformLambda, cfnLambda — added later */];
const oracles = { sdk: checkSdk, cli: checkCli };

// Per-oracle timeout — see the block comment: the first invoke absorbs the
// MiniStack Lambda cold start, which the 60s default testTimeout can't cover.
const ORACLE_TIMEOUT_MS = 120_000;

describe.each(adapters)('lambda provisioned via $name', (adapter) => {
  let c: LambdaContract;

  beforeAll(async () => {
    c = await adapter.deploy();
  }, 300_000);

  afterAll(async () => {
    await adapter.teardown?.();
  });

  it.each(Object.entries(oracles))(
    'passes the %s oracle',
    (_name, oracle) => oracle(c),
    ORACLE_TIMEOUT_MS,
  );
});
