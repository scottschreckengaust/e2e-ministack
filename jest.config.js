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
  // Resolve extension-less imports to the TypeScript SOURCE (`.ts`) before a
  // sibling `.mjs` CLI shim of the same basename (#165). A helper script is a
  // pair — `<name>.ts` (tested logic) + `<name>.mjs` (thin CLI). Jest's DEFAULT
  // moduleFileExtensions order puts `mjs` BEFORE `ts`, so an extension-less
  // import like `../../scripts/ministack-upstream` would resolve to the `.mjs`
  // (native ESM → "Cannot use import statement outside a module"). Putting
  // `ts`/`tsx` FIRST makes jest load — and istanbul/Stryker instrument — the
  // `.ts` source, which is the file the code actually IS. (The logic modules
  // are excluded from the emitting tsconfig, so no compiled `.js` sibling
  // exists to shadow the `.ts` under Stryker; see tsconfig.json / #165.)
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
    // The EXCLUSION IS FOR I/O, NOT FOR SKIPPING TESTS. The harness-wide policy
    // (#151/#144, see services/README.md § Coverage): EXTRACT pure logic to a
    // gated (coverage-INCLUDED) module; keep only genuine I/O in the excluded
    // shell; NEVER mock the emulator/CLI/SDK to chase coverage. The excluded
    // shells here are THIN — their pure payload/response/argv/classification
    // logic lives in gated siblings (e.g. services/lambda/invoke.ts,
    // services/*/health.ts, services/_harness/*.ts) unit-tested without an
    // emulator. Any OTHER pure logic under services/ stays gated at 100%, so a
    // helper named anything but `checks.*.ts` / `iac/**/deploy.ts` is INCLUDED
    // by default — which is why the extracted seams need no glob edit here.
    'services/**/*.{ts,js}',
    '!services/**/*.test.ts',
    '!services/**/checks.*.ts',
    '!services/**/iac/**/deploy.ts',
    // Helper-script logic modules (#165). The security-critical parsers/deciders
    // in .github/scripts/ + scripts/ used to be `.mjs` spawned via a subprocess
    // (istanbul can't instrument a child process), or run by `node --test`
    // (never invoked in CI). Their PURE logic now lives in `.ts` siblings that
    // jest imports IN-PROCESS, so they flow through this 100% gate + Stryker.
    // These are PATH-CONVENTION includes, so FUTURE helper scripts inherit the
    // gates automatically — add a `.ts` logic module + an in-process spec and
    // it is gated with no further jest.config edits. The runnable `.mjs` CLI
    // shims (argv/read/write/exit only; Node strips the `.ts` on import at
    // workflow time — no build step) and network-only I/O are NOT collectable
    // in-process and are excluded by the `**/*.ts`-only globs here.
    // `.ts`-only: `moduleFileExtensions` above makes jest load the TS source,
    // so istanbul instruments the `.ts` directly (and Stryker mutates the same
    // file jest loads). The runnable `.mjs` CLI shims and network-only I/O are
    // not `.ts`, so these globs exclude them automatically.
    '.github/scripts/**/*.ts',
    '!.github/scripts/**/*.test.ts',
    'scripts/**/*.ts',
    '!scripts/**/*.test.ts',
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
