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
  // Pin the fast-check global seed so the property tests are deterministic
  // across runs/triggers (otherwise the seed is Date.now()^Math.random() and
  // the gate is flaky). See test/setup.fast-check.ts.
  setupFilesAfterEnv: ['<rootDir>/test/setup.fast-check.ts'],
  // MiniStack deploys/invocations can take a few seconds; unit is fast.
  testTimeout: tier === 'unit' ? 15000 : 60000,
  // Emit a JUnit report per tier so CI can upload it as an artifact even on
  // failure (and surface it in test-report UIs).
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: 'reports/junit',
        outputName: `${tier}.xml`,
        suiteName: `${tier} tests`,
      },
    ],
  ],
};
