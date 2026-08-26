import js from '@eslint/js';
import tseslint from 'typescript-eslint';

export default tseslint.config(
  {
    // Generated/vendored output and local tooling — never lint these.
    ignores: [
      'node_modules/**',
      'cdk.out/**',
      '.remember/**',
      '**/*.js',
      '**/*.d.ts',
    ],
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        // The fuzz-regression `.ts` targets (#165) are deliberately kept out of
        // the emitting tsconfig (so no compiled `.js` shadows a `.ts` under
        // jest/Stryker), so the project service can't find them in a tsconfig's
        // `include`; `allowDefaultProject` lets them lint under an inferred
        // default program instead. (The other excluded logic modules under
        // .github/scripts/ + scripts/ are reachable via their test imports, so
        // the service already covers them.)
        projectService: {
          // `fuzz/*.regression.test.ts`: the fuzz-regression targets (see the
          // exclude comment above). `.github/scripts/vex-dialects.ts` +
          // `test/unit/vex-dialects.test.ts` (#251): both are excluded from the
          // EMITTING tsconfig.json (vex-dialects.ts does a runtime `.ts`
          // value cross-import the emitting build can't follow — TS5097), and
          // the test is the ONLY importer of that module, so neither is
          // reachable through a tsconfig.json test-import the way the other
          // logic modules are. They ARE type-checked by tsconfig.scripts.json;
          // here they lint under the inferred default program.
          allowDefaultProject: [
            'fuzz/*.regression.test.ts',
            '.github/scripts/vex-dialects.ts',
            'test/unit/vex-dialects.test.ts',
            // #295: same `.ts` value cross-import situation — npm-audit-gate.ts
            // and npm-audit-to-sarif.ts import ./vex-ledger.ts with an explicit
            // extension, so they + their sole-importer unit tests are excluded
            // from the emitting tsconfig.json and lint under the inferred program.
            '.github/scripts/npm-audit-gate.ts',
            '.github/scripts/npm-audit-to-sarif.ts',
            'test/unit/npm-audit-gate.test.ts',
            'test/unit/npm-audit-to-sarif.test.ts',
            // #336: likewise — vex-revisit-gate.ts imports ./vex-ledger.ts,
            // ./vex-to-sarif-suppressions.ts and ./npm-audit-gate.ts with
            // explicit `.ts` extensions, so it + its sole-importer unit test are
            // excluded from the emitting tsconfig.json and lint here.
            '.github/scripts/vex-revisit-gate.ts',
            'test/unit/vex-revisit-gate.test.ts',
            // #337: grype-fs-gate.ts was self-contained (NO imports) until the
            // purl-scoped coverage decision moved it onto the shared ledger — it
            // now imports ./vex-ledger.ts with an explicit `.ts` extension, so it
            // + its sole-importer unit test joined the emitting tsconfig.json's
            // exclude list and lint here instead.
            '.github/scripts/grype-fs-gate.ts',
            'test/unit/grype-fs-gate.test.ts',
            // #342: same again for vex-report.ts, which now imports
            // ./vex-ledger.ts with an explicit `.ts` extension (the overdue
            // verdict is delegated to the ledger core instead of re-derived).
            // alerts-findings.ts joins it because it imports vex-report.ts, so
            // the `.ts`-specifier graph reaches it transitively. NOTE these two
            // MODULES were previously covered incidentally — the project service
            // reached them through their unit tests, which were still inside the
            // emitting tsconfig.json. Excluding the tests (TS5097) drops that
            // path, so module + test must both be named here.
            '.github/scripts/vex-report.ts',
            '.github/scripts/alerts-findings.ts',
            'test/unit/vex-report.test.ts',
            'test/unit/alerts-findings.test.ts',
            // #352: vex-debian-tracker.ts imports ./vex-ledger.ts with an
            // explicit `.ts` extension for the same reason (it reuses the
            // ledger's purl parser + record discovery rather than re-deriving
            // them), so module + sole-importer test lint here.
            '.github/scripts/vex-debian-tracker.ts',
            'test/unit/vex-debian-tracker.test.ts',
          ],
          // typescript-eslint caps the inferred default program at 8 matched
          // files by default; the fuzz-regression `.ts` targets (one per logic
          // module) crossed that ceiling at #284 (the grype-fs-gate target is the
          // 9th). These are tiny corpus-replay specs, so the perf cost of a
          // slightly larger default program is negligible — raise the cap rather
          // than move them into an emitting tsconfig (which would resurrect the
          // `.js`-shadows-`.ts` problem #165 avoids). Raised again at #336, and
          // at #337 (the 13 fuzz targets + 10 named entries = 23 matched files),
          // and at #342 (14 named entries = 27), and at #352 (16 named = 29);
          // keep a little headroom so the next logic module doesn't have to
          // touch this line.
          maximumDefaultProjectFileMatchCount_THIS_WILL_SLOW_DOWN_LINTING: 34,
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);
