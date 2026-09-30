import { defineConfig } from 'vitest/config';

/**
 * The Node suite runs the client against the real WASM module that
 * `build-wasm.mjs` writes to `test/browser/pkg`: `test:browser` builds it in
 * CI, and `test:node:local` builds it before a local run.
 */
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['**/*.test.ts'],
    environment: 'node',
  },
});
