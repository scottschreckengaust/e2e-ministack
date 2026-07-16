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
  // Scope also includes the helper-script LOGIC modules (#165): the two SARIF
  // parsers, the SPDX allow-list decider, and the upstream-tracker pure logic.
  // These are input→output transformers whose output is load-bearing for
  // security (a wrong SARIF hides Code Scanning alerts; a wrong license verdict
  // wrongly closes/escalates a review issue), so they are the IDEAL mutation
  // targets — arguably more than the trivial doubler. The maintainer bar for
  // #165 is 0 SURVIVING mutants on these files. Their unit specs import the
  // `.ts` IN-PROCESS (test/unit/{clamav,sonar}-to-sarif.test.ts,
  // license-verdict.test.ts, ministack-upstream.test.ts), so Stryker's
  // jest-runner mutates them against the unit tier with no extra tooling. The
  // thin `.mjs` CLI shims and network-only I/O are deliberately NOT here (no
  // in-process coverage → Stryker would report them as "no coverage" noise).
  mutate: [
    'lambda/index.js',
    '.github/scripts/clamav-to-sarif.ts',
    '.github/scripts/sonar-to-sarif.ts',
    '.github/scripts/vex-to-sarif-suppressions.ts',
    '.github/scripts/vex-report.ts',
    '.github/scripts/alerts-findings.ts',
    '.github/scripts/sarif-cve-ids.ts',
    '.github/scripts/gate-findings.ts',
    '.github/scripts/license-verdict.ts',
    'scripts/ministack-upstream.ts',
  ],
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
