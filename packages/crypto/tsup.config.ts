import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  // Bundle all dependencies into the CJS output so CommonJS consumers
  // (NestJS API, Jest) don't hit ERR_PACKAGE_PATH_NOT_EXPORTED or
  // "Unexpected token export" from ESM-only deps (@noble/*, @libp2p/*, ipns, multiformats).
  noExternal: [/.*/],
});
