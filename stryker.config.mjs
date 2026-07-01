// Stryker mutation testing config.
// Run: npm run test:mutation
//
// Mutates the doubler logic and the CDK stack, then runs the UNIT tier
// (synth-only, no MiniStack) to see which mutants survive. A surviving mutant
// means a test gap. Incremental mode caches per-mutant verdicts so subsequent
// runs only re-test changed files.
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  testRunner: 'jest',
  jest: {
    // Reuse the project's jest config; force the fast, emulator-free unit tier.
    projectType: 'custom',
    configFile: 'jest.config.js',
  },
  // Scope: the Lambda's pure logic only. The CDK stack (lib/) is declarative
  // config — Stryker can't tie a construct-source mutation to the synthesized
  // template (mutants register as "no coverage"), so mutating it adds noise,
  // not signal. The stack is covered instead by cdk-nag, checkov, fine-grained
  // CDK assertions, and the template snapshot. Add lib/ back here only if the
  // stack grows real computed logic (loops/conditionals/helpers).
  mutate: ['lambda/index.js'],
  // Speed: cache verdicts and re-test only mutants in changed files.
  incremental: true,
  incrementalFile: 'reports/mutation/incremental.json',
  // `json` emits reports/mutation/mutation.json in the cross-language
  // mutation-testing-report-schema — the machine-readable report CI parses
  // for the step summary (no JUnit reporter exists for Stryker, by design).
  reporters: ['html', 'clear-text', 'progress', 'json'],
  jsonReporter: { fileName: 'reports/mutation/mutation.json' },
  // CI gate: fail under 80%, warn under 90%.
  thresholds: { high: 90, low: 80, break: 80 },
  // jest-runner needs JEST_TIER=unit; set via env in the npm script.
};
