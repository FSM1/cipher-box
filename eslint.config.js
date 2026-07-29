import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import pluginPrettier from 'eslint-plugin-prettier/recommended';

export default [
  {
    ignores: [
      '**/dist/**',
      '**/node_modules/**',
      '**/.planning/**',
      '**/.claude/**',
      '**/00-Preliminary-R&D/**',
      '**/Preliminary/**',
      '**/.learnings/**',
      '**/src-tauri/target/**',
      'target/**',
      // Generated wasm-bindgen glue + Playwright output for the browser suite.
      'apps/web/src/wasm/**',
      '**/test/browser/pkg/**',
      '**/playwright-report/**',
      '**/test-results/**',
      // Astro build output in the standalone landing site (git-ignored, generated).
      '**/.astro/**',
    ],
  },
  { files: ['**/*.{js,mjs,cjs,mts,cts,ts,tsx}'] },
  { languageOptions: { globals: { ...globals.browser, ...globals.node } } },
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  pluginPrettier,
  {
    rules: {
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/no-explicit-any': 'warn',
    },
  },
];
