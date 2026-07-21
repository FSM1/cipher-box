import { configDefaults, defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The unit suite: fake-backed Nest specs, no real Postgres. `*.test.ts` would
// otherwise also match `*.integration.test.ts` and `*.scheduled.test.ts`, so
// those are excluded here and run only in their own jobs (see
// vitest.integration.config.ts and vitest.scheduled.config.ts).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [
      ...configDefaults.exclude,
      'src/**/*.integration.test.ts',
      'src/**/*.scheduled.test.ts',
    ],
    environment: 'node',
  },
  plugins: [swcPlugin()],
});
