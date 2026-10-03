import { defineConfig } from 'vitest/config';

// The unit suite covers the operator tools and the pure staging modules; every
// `*.spec.ts` here is Playwright's.
export default defineConfig({
  test: {
    include: ['tools/**/*.test.ts', 'staging/**/*.test.ts'],
  },
});
