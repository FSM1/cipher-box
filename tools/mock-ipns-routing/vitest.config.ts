import { defineConfig } from 'vitest/config';

// The store's unit suite: the monotonic-sequence rule the PUT route enforces.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
  },
});
