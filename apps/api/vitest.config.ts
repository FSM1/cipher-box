import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

// NestJS dependency injection needs emitDecoratorMetadata, which esbuild
// (vitest's default transform) cannot emit — so tests compile through SWC.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
  plugins: [
    swc.vite({
      jsc: {
        parser: { syntax: 'typescript', decorators: true },
        transform: { legacyDecorator: true, decoratorMetadata: true },
        target: 'es2022',
      },
      module: { type: 'es6' },
    }),
  ],
});
