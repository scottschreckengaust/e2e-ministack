// End-to-end tests against a REAL AWS account (not MiniStack).
//
// Planned tier — the top of the pyramid, above the MiniStack integration tests.
// It deploys the stack to an actual account and exercises the live resources.
// Tracked in #176; not yet implemented (the repo runs only against MiniStack —
// no real account today, a deliberate scope decision: AGENTS.md "Not used here
// (would need a real AWS account)", epic #117 non-goal "No real-account stage").
//
// These are `it.todo` markers, NOT skipped stubs: they declare the intended
// cases as pending work without asserting anything (no tautological
// `expect(true).toBe(true)`), so they show as "todo" in the report rather than
// as passing or silently skipped. Replace each with a real test when #176 lands.
//
// To implement (#176):
//   1. Deploy to a throwaway/staging account (cdk deploy, real credentials,
//      NO AWS_ENDPOINT_URL override).
//   2. Point the SDK clients at real AWS (drop the endpoint override).
//   3. Assert on the live resources, then `cdk destroy` to clean up.
//   Gate behind an env flag (e.g. RUN_E2E=1) so it runs only in that stage.

describe('e2e (real AWS account)', () => {
  it.todo('deploys and invokes the Lambda against real AWS (#176)');
  it.todo('round-trips an object through the deployed S3 bucket (#176)');
});
