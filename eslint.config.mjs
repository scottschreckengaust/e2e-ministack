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
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
  },
);
