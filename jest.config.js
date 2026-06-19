module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/test/**/*.test.ts'],
  // Deploys/invocations against MiniStack can take a few seconds.
  testTimeout: 60000,
};
