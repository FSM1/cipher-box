import { defineConfig } from 'vitest/config';

// The unit suite covers the operator tools and the pure soak modules; every
// `*.spec.ts` here is Playwright's.
export default defineConfig({
  test: {
    include: ['tools/**/*.test.ts', 'staging/soak/**/*.test.ts'],
  },
});
