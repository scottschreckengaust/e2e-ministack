// Dedicated Jest config for the fuzz-corpus *regression* tier.
// Run: npm run test:fuzz-regression
//
// WHY A SEPARATE CONFIG (not a `projects` entry in jest.config.js): the shared
// jest.config.js is also driven programmatically by Stryker for every mutant
// (`test:mutation`) and via `JEST_TIER` for the unit/integration tiers, and it
// enforces the 100% `coverageThreshold` gate. Keeping the corpus-replay tier in
// its own config + npm script + CI step is the low-blast-radius choice: Stryker
// and the unit coverage gate never see this tier, and this tier collects no
// coverage of its own (lambda/index.js is already at 100% from the unit tier).
//
// This uses Jest's DEFAULT test runner — plain Jest, no @jazzer.js/jest-runner
// (that runner is incompatible with jest@30; see fuzz/handler.regression.test.js
// and issue #126). The test itself replays fuzz/corpus/ via jazzer's
// FuzzedDataProvider, so no native libFuzzer addon is needed and it runs on any
// host (unlike the exploratory scheduled jazzer job).
module.exports = {
  // ts-jest so the SARIF-parser fuzz-regression targets (#165) can import the
  // TypeScript logic modules (.github/scripts/*.ts) in-process, exactly like
  // the unit tier. The original plain-JS handler replay
  // (handler.regression.test.js) still runs unchanged — ts-jest transforms
  // `.ts`/`.tsx` and leaves plain `.js` alone. `moduleFileExtensions` matches
  // the unit config so an extension-less script import resolves to the `.ts`
  // logic module, never its sibling `.mjs` CLI shim.
  preset: 'ts-jest',
  testEnvironment: 'node',
  moduleFileExtensions: [
    'ts',
    'tsx',
    'js',
    'mjs',
    'cjs',
    'jsx',
    'json',
    'node',
  ],
  // The corpus-replay regression tests: the plain-JS Lambda handler replay plus
  // the TypeScript SARIF-parser replays (#165).
  roots: ['<rootDir>/fuzz'],
  testMatch: ['**/*.regression.test.js', '**/*.regression.test.ts'],
  testTimeout: 15000,
  // No coverage / NO coverageThreshold here — this tier is a robustness gate,
  // not a coverage source. The 100% coverage gate lives in the unit tier only.
  collectCoverage: false,
  // Emit reports/junit/fuzz.xml so the fuzz-regression tier joins the polyglot
  // reporting contract (docs/TESTING.md) and is uploaded like unit.xml /
  // integration.xml. One <testcase> per replayed corpus input.
  reporters: [
    'default',
    [
      'jest-junit',
      {
        outputDirectory: 'reports/junit',
        outputName: 'fuzz.xml',
        suiteName: 'fuzz regression tests',
      },
    ],
  ],
};
