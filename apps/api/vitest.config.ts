import { configDefaults, defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The unit suite: fake-backed Nest specs, no real Postgres. `*.test.ts` would
// otherwise also match `*.integration.test.ts`, so those are excluded here and
// run only in the dedicated real-Postgres job (see vitest.integration.config.ts).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'src/**/*.integration.test.ts'],
    environment: 'node',
  },
  plugins: [swcPlugin()],
});
