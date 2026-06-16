import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: false, // emitted via a blocking tsc pass (build script); tsup's concurrent dts intermittently no-ops on Windows CI
  clean: true,
  sourcemap: true,
});
