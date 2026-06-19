// End-to-end tests against a REAL AWS account (not MiniStack).
//
// Placeholder: this tier deploys the stack to an actual account and exercises
// the live resources — the top of the pyramid above the MiniStack integration
// tests. It is `describe.skip` so CI stays green until a real-account stage
// exists. To implement:
//   1. Deploy to a throwaway/staging account (cdk deploy, real credentials,
//      NO AWS_ENDPOINT_URL override).
//   2. Point the SDK clients at real AWS (drop the endpoint override).
//   3. Assert on the live resources, then `cdk destroy` to clean up.
// Gate it behind an env flag (e.g. RUN_E2E=1) so it only runs in that stage.

describe.skip('e2e (real AWS account) — not yet implemented', () => {
  it('deploys and invokes the Lambda against real AWS', () => {
    // TODO: implement once a real-account stage is introduced.
    expect(true).toBe(true);
  });
});
