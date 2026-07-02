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
 * A `DeployAdapter<C>` provisions a resource (or short-circuits if it is
 * already up) and returns the typed {@link Contract} the shared oracles run
 * against. One adapter is authored per (service × IaC tool).
 *
 * The generic `C` lets each vertical specialize the returned contract (e.g.
 * `DeployAdapter<LambdaContract>`) while every adapter still satisfies this one
 * uniform interface — so `test/integration/services/*.test.ts` can
 * `describe.each(adapters)` over a heterogeneous list.
 *
 * CDK adapters may **short-circuit**: CI runs `cdk deploy` before the
 * integration tier today, so `deploy()` can return the contract for an
 * already-deployed resource without redeploying. Other tools (Terraform,
 * CloudFormation, …) do the real `apply`/`deploy` work inside `deploy()`.
 */
export interface DeployAdapter<C extends Contract = Contract> {
  /** IaC tool identity, e.g. `'cdk' | 'terraform' | 'cloudformation'`. */
  name: string;
  /** Provision (or reuse) the resource and return its contract. */
  deploy(): Promise<C>;
  /** Optional cleanup; omitted when the resource is shared/pre-deployed. */
  teardown?(): Promise<void>;
}
