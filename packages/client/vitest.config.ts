import { defineConfig } from 'vitest/config';

/**
 * Vitest covers only the `src` unit tests. The browser suite lives under
 * `test/browser` and runs under Playwright (real IndexedDB/OPFS), not Vitest —
 * scope the include so Vitest never tries to run the Playwright specs in Node.
 */
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
