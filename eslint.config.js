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
  // D-07 web/SDK import boundary (SC3a) — CI-enforced via `pnpm lint`, replacing the
  // bespoke grep gate. apps/web/src must stay on the @cipherbox/sdk facade and off raw
  // read-chain/IPFS internals. Scoped to apps/web/src, ignoring test files.
  {
    files: ['apps/web/src/**/*.{ts,tsx}'],
    ignores: ['apps/web/src/**/__tests__/**'],
    rules: {
      // Gate A: no runtime imports of sdk-core/core (type-only imports remain allowed).
      '@typescript-eslint/no-restricted-imports': [
        'error',
        {
          patterns: [
            {
              group: ['@cipherbox/sdk-core', '@cipherbox/core'],
              message:
                'apps/web/src must not import runtime bindings from @cipherbox/sdk-core or ' +
                '@cipherbox/core (D-07 boundary) — use the @cipherbox/sdk facade instead.',
              allowTypeImports: true,
            },
          ],
        },
      ],
      // Gate B: no raw IPFS calls by name (import rule cannot cover freshly-inlined calls).
      'no-restricted-syntax': [
        'error',
        {
          selector: 'CallExpression[callee.name=/^(fetchFromIpfs|addToIpfs|unpinFromIpfs)$/]',
          message:
            'Raw IPFS calls are forbidden in apps/web/src (D-07) — use the SDK client facade.',
        },
      ],
    },
  },
];
