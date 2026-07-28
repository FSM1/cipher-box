import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    // `.tsx` is explicit: the component suites are invisible to a `.test.ts`
    // include and would be skipped in CI without ever failing.
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
