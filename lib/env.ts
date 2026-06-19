import * as cdk from 'aws-cdk-lib';

/**
 * The fixed AWS environment this app targets: the MiniStack emulator's
 * well-known dummy account (000000000000, the same sentinel LocalStack uses)
 * in us-east-1.
 *
 * This is a hard constant on purpose — see issue #2. The CDK CLI populates
 * `CDK_DEFAULT_ACCOUNT`/`CDK_DEFAULT_REGION` by resolving the *ambient*
 * credential chain (AWS_PROFILE / SSO / IMDS) before it runs the app, so
 * reading those env vars would let a contributor's real account silently
 * become the synth/deploy target. For a MiniStack-only repo the target is
 * known and fixed, which is exactly the case the AWS CDK docs say to hardcode.
 *
 * Single source of truth: `bin/app.ts` and the unit tests both import this so
 * the literal `000000000000` is never duplicated and can never drift. The
 * `bootstrap` npm script (`aws://000000000000/us-east-1`) must match it.
 */
export const MINISTACK_ENV: Required<
  Pick<cdk.Environment, 'account' | 'region'>
> = {
  account: '000000000000',
  region: 'us-east-1',
};
