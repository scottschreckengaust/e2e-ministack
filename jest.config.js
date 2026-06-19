// Test tiers (pyramid, fast → slow):
//   test:unit        — pure logic + CDK assertions/snapshot (no emulator)
//   test:integration — AWS SDK against deployed MiniStack resources
//   test:e2e         — real AWS account (placeholder)
// Select a tier with the JEST_TIER env var (set by the npm scripts), or run
// the default (unit) directly.
const tier = process.env.JEST_TIER || 'unit';

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // allow importing the plain-JS Lambda handler from the TS unit test
  roots: [`<rootDir>/test/${tier}`],
  testMatch: ['**/*.test.ts'],
  // MiniStack deploys/invocations can take a few seconds; unit is fast.
  testTimeout: tier === 'unit' ? 15000 : 60000,
};
