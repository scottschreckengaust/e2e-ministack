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
          allowDefaultProject: ['fuzz/*.regression.test.ts'],
          // typescript-eslint caps the inferred default program at 8 matched
          // files by default; the fuzz-regression `.ts` targets (one per logic
          // module) crossed that ceiling at #284 (the grype-fs-gate target is the
          // 9th). These are tiny corpus-replay specs, so the perf cost of a
          // slightly larger default program is negligible — raise the cap rather
          // than move them into an emitting tsconfig (which would resurrect the
          // `.js`-shadows-`.ts` problem #165 avoids).
          maximumDefaultProjectFileMatchCount_THIS_WILL_SLOW_DOWN_LINTING: 20,
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);
