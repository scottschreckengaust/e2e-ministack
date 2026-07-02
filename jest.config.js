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
  // Coverage (unit tier only). Collection is switched ON by the npm script
  // (`test:unit` passes --coverage), deliberately NOT by `collectCoverage:
  // true` here: Stryker runs jest programmatically through this same config
  // for every mutant, and always-on coverage would both slow every mutant run
  // and corrupt mutation semantics (a mutant could be "killed" by the
  // coverageThreshold failure below instead of a real assertion). The
  // integration tier can't collect coverage at all — the code under test runs
  // inside MiniStack's Lambda container, where istanbul can't see it (#124).
  // Both .ts and the tsc-compiled .js siblings must be listed for lib/bin:
  // tsc compiles in place and Jest resolves `../../lib/env` to the compiled
  // .js when it exists (default moduleFileExtensions puts js before ts), so
  // .ts-only globs would silently collect nothing from lib/bin after a build
  // (as in CI, where `npm run build` precedes `npm run test:unit`). With the
  // .js globs istanbul instruments whichever file was executed and inline
  // source maps (tsconfig `inlineSourceMap`) remap the report to the .ts
  // sources either way.
  collectCoverageFrom: [
    'lambda/**/*.js',
    'lib/**/*.{ts,js}',
    'bin/**/*.{ts,js}',
    // MiniStack compatibility harness (services/, #135). Pure logic here is
    // 100%-gated like lib/bin, but code that only runs in the INTEGRATION tier
    // is excluded — istanbul can't see it from the unit tier (same reason the
    // integration tier collects zero coverage: it executes against a live
    // MiniStack, e.g. inside its Lambda container). These are PATH-CONVENTION
    // excludes, so later verticals (#136+) need no further jest.config edits:
    //   checks.*.ts        — SDK/CLI oracles (integration-tier, live MiniStack)
    //   iac/**/deploy.ts   — DeployAdapters (integration-tier provisioners)
    //   *.test.ts          — spec files
    // Any OTHER pure logic under services/ stays gated at 100%.
    'services/**/*.{ts,js}',
    '!services/**/*.test.ts',
    '!services/**/checks.*.ts',
    '!services/**/iac/**/deploy.ts',
    // Type declarations (the hand-written lambda/index.d.ts contract) carry
    // no executable code.
    '!**/*.d.ts',
  ],
  // Under the gitignored reports/ tree, next to junit/ and mutation/.
  coverageDirectory: 'reports/coverage',
  // lcov is the interchange format phase 2 (#125) consumes; json-summary
  // feeds the GITHUB_STEP_SUMMARY block in CI; text prints in the job log.
  coverageReporters: ['text', 'lcov', 'json-summary'],
  // Hard gate: 100% on the unit tier (maintainer decision, #122). Enforced in
  // the tool (jest exits non-zero) per produce → always-upload → enforce.
  coverageThreshold: {
    global: { branches: 100, functions: 100, lines: 100, statements: 100 },
  },
};
