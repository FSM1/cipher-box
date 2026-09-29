import { defineConfig } from 'vitest/config';

/**
 * Reads the production module that `apps/web`'s `build:wasm` writes, so it
 * runs in the Web Bundle job, which holds that artifact.
 */
export default defineConfig({
  test: {
    root: import.meta.dirname,
    include: ['**/*.test.ts'],
    environment: 'node',
  },
});
