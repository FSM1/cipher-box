import { defineConfig } from 'tsup';

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['cjs'],
    clean: true,
    sourcemap: true,
    dts: true,
    // Bundle all dependencies into the CJS output so CommonJS consumers
    // (NestJS API, Jest) don't hit ERR_PACKAGE_PATH_NOT_EXPORTED or
    // "Unexpected token export" from ESM-only deps (@noble/*, @libp2p/*, ipns, multiformats).
    noExternal: [/.*/],
  },
  {
    entry: ['src/index.ts'],
    format: ['esm'],
    sourcemap: true,
    dts: true,
    // ESM output leaves deps external — Vite/browser bundlers handle them natively.
  },
]);
