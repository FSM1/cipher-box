import { configDefaults, defineConfig } from 'vitest/config';
import { swcPlugin } from './vitest.swc';

// The unit suite: fake-backed Nest specs, no real Postgres. `*.scheduled.test.ts`
// matches the include glob but owns its own tier (see vitest.scheduled.config.ts).
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: [...configDefaults.exclude, 'src/**/*.scheduled.test.ts'],
    environment: 'node',
  },
  plugins: [swcPlugin()],
});
