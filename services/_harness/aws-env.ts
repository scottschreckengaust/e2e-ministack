/**
 * Shared MiniStack AWS-toolchain env defaults for the compatibility harness
 * (epic #117, #147).
 *
 * This is the SINGLE source of the MiniStack endpoint / region / dummy-credential
 * defaults. The CDK deploy adapter (iac/**\/deploy.ts) and the SDK/CLI oracles
 * (checks.*.ts) each need the same "point the AWS toolchain at MiniStack"
 * fallbacks; without this module every one of them re-implements the identical
 * `?? 'http://localhost:4566'` / `?? 'us-east-1'` / `?? 'test'` literals, which
 * is exactly the kind of copy-paste drift #147 extracts away. Pure functions
 * over an explicit `env` param (no module-load `process.env` reads) so they are
 * unit-testable and held at the repo's 100% coverage gate.
 */

/** MiniStack serves the full AWS surface on this single local endpoint. */
export const MINISTACK_DEFAULT_ENDPOINT = 'http://localhost:4566';

/**
 * The AWS endpoint to talk to: the caller's `AWS_ENDPOINT_URL` if set, else the
 * MiniStack default.
 */
export function endpoint(env: NodeJS.ProcessEnv): string {
  return env.AWS_ENDPOINT_URL ?? MINISTACK_DEFAULT_ENDPOINT;
}

/** The AWS region: the caller's `AWS_DEFAULT_REGION` if set, else `us-east-1`. */
export function region(env: NodeJS.ProcessEnv): string {
  return env.AWS_DEFAULT_REGION ?? 'us-east-1';
}

/**
 * A copy of `env` with every MiniStack default backfilled: the generic endpoint,
 * both region vars, and the dummy static credentials MiniStack accepts. Other
 * keys pass through unchanged. Used to spawn the `cdk`/AWS-CLI child processes so
 * they hit MiniStack even when the ambient env only sets a subset.
 */
export function ministackEnv(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  return {
    ...env,
    AWS_ENDPOINT_URL: env.AWS_ENDPOINT_URL ?? MINISTACK_DEFAULT_ENDPOINT,
    AWS_REGION: env.AWS_REGION ?? 'us-east-1',
    AWS_DEFAULT_REGION: env.AWS_DEFAULT_REGION ?? 'us-east-1',
    AWS_ACCESS_KEY_ID: env.AWS_ACCESS_KEY_ID ?? 'test',
    AWS_SECRET_ACCESS_KEY: env.AWS_SECRET_ACCESS_KEY ?? 'test',
  };
}
