import { defineConfig } from 'tsup';

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  // Bundle ESM-only dependencies into the CJS output so consumers
  // like the NestJS API (CommonJS) can require('@cipherbox/crypto')
  // without hitting ERR_PACKAGE_PATH_NOT_EXPORTED errors.
  noExternal: ['@libp2p/crypto', '@libp2p/peer-id', 'multiformats'],
});
