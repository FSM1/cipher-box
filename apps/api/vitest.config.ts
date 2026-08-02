import { configDefaults, defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The unit suite: fake-backed Nest specs, no real Postgres. The integration
// tier's `*.itest.ts` files fall outside this `*.test.ts` glob already, but
// `*.scheduled.test.ts` matches it, so that tier is excluded here and runs in
// its own job (see vitest.scheduled.config.ts).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'src/**/*.scheduled.test.ts'],
    environment: 'node',
  },
  plugins: [swcPlugin()],
});
