import { defineConfig } from 'vitest/config';

// The unit suite covers the operator tools, the page-object waits and the pure
// staging modules; every `*.spec.ts` here is Playwright's.
export default defineConfig({
  test: {
    include: ['tools/**/*.test.ts', 'page-objects/**/*.test.ts', 'staging/**/*.test.ts'],
  },
});
