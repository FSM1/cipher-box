import { defineConfig } from 'tsup';

export default defineConfig({
  // Two entries: the main barrel, and the browser-only IndexedDB rotation
  // adapter as its OWN entry (`@cipherbox/sdk/state/rotation-idb-store`) so
  // IndexedDB is never pulled into desktop/node consumers of the main barrel
  // and the adapter stays tree-shakeable (70.1-02).
  entry: ['src/index.ts', 'src/state/rotation-idb-store.ts'],
  format: ['cjs', 'esm'],
  dts: false, // emitted via a blocking tsc pass (build script); tsup's concurrent dts intermittently no-ops on Windows CI
  clean: true,
  sourcemap: true,
});
