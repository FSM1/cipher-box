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
    ],
  },
  { files: ['**/*.{js,mjs,cjs,ts,tsx}'] },
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
