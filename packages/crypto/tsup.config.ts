import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs'],
    clean: true,
    sourcemap: true,
    dts: false, // emitted via a blocking tsc pass (build script); tsup's concurrent dts intermittently no-ops on Windows CI
    // Bundle all dependencies into the CJS output so CommonJS consumers
    // (NestJS API, Jest) don't hit ERR_PACKAGE_PATH_NOT_EXPORTED or
    // "Unexpected token export" from ESM-only deps (@noble/*, @libp2p/*, ipns, multiformats).
    noExternal: [/.*/],
  },
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    sourcemap: true,
    dts: false, // emitted via a blocking tsc pass (build script); tsup's concurrent dts intermittently no-ops on Windows CI
    // ESM output leaves deps external — Vite/browser bundlers handle them natively.
  },
]);
