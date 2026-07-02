// Core interfaces for the per-resource MiniStack compatibility harness
// (epic #117, sub-issue A / #135). These are the two seams every later
// service/IaC vertical (#136+) plugs into:
//
//   Contract       — the per-service handle an adapter returns and an oracle
//                    consumes; the ONLY thing that crosses the deploy⇄verify
//                    boundary, which is what keeps oracles IaC-tool-agnostic.
//   DeployAdapter  — the uniform provisioning interface each IaC tool (cdk /
//                    terraform / cloudformation / …) implements once.
//
// This file is types-only. TypeScript interfaces and type aliases erase to
// zero runtime statements, so it contributes nothing to the unit-tier
// coverage gate — the harness scaffolding compiles under `tsc` but is
// exercised for real only by the integration-tier verticals.

/**
 * A `Contract` is the typed handle to a provisioned resource. It is
 * intentionally an open marker type: each vertical narrows it to the minimal
 * shape its oracles need, e.g.
 *
 * ```ts
 * type LambdaContract = Contract & { functionName: string };
 * ```
 *
 * An oracle takes a `Contract` (its specialized form) and asserts behavior; it
 * never knows which IaC tool produced it. That indirection is what lets one
 * SDK/CLI oracle be shared across CDK, Terraform, CloudFormation, and beyond.
 */
export type Contract = Record<string, unknown>;

/**
 * A `DeployAdapter<C>` provisions a resource (verifying first, provisioning if
 * absent) and returns the typed {@link Contract} the shared oracles run against.
 * One adapter is authored per (service × IaC tool).
 *
 * The generic `C` lets each vertical specialize the returned contract (e.g.
 * `DeployAdapter<LambdaContract>`) while every adapter still satisfies this one
 * uniform interface — so `test/integration/services/*.test.ts` can
 * `describe.each(adapters)` over a heterogeneous list.
 *
 * **VERIFY-OR-PROVISION — the per-vertical self-provisioning model (#147).**
 * Each vertical OWNS and SELF-PROVISIONS its own IaC artifact(s); the topology
 * is agnostic (single stack, multiple stacks, nested, or cross-app-via-outputs).
 * `deploy()` verifies the resource exists (fast path, no rework) and provisions
 * it if absent, then returns the `Contract`. The CDK Lambda adapter does exactly
 * this against its own `CompatLambdaStack` (distinct `compat-*` physical name),
 * fully decoupled from the demo stack `lib/ministack-stack.ts` — it no longer
 * relies on CI having run `cdk deploy` of the demo stack first. Terraform /
 * CloudFormation adapters do their tool's own `apply`/`deploy` inside `deploy()`
 * the same way. This interface is UNCHANGED — provisioning is entirely the
 * adapter's concern, which is what keeps the oracles IaC-tool-agnostic.
 */
export interface DeployAdapter<C extends Contract = Contract> {
  /** IaC tool identity, e.g. `'cdk' | 'terraform' | 'cloudformation'`. */
  name: string;
  /** Verify-or-provision the resource and return its contract. */
  deploy(): Promise<C>;
  /**
   * Optional cleanup. Omitted when reset is delegated to
   * `POST /_ministack/reset` (the upstream cross-vertical pattern) or when the
   * adapter must not tear down what it did not provision.
   */
  teardown?(): Promise<void>;
}
