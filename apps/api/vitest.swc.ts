import swc from 'unplugin-swc';

// NestJS dependency injection needs emitDecoratorMetadata, which esbuild
// (vitest's default transform) cannot emit — so tests compile through SWC.
// Shared by the unit and integration vitest configs so the transform can't drift.
export function swcPlugin() {
  return swc.vite({
    jsc: {
      parser: { syntax: 'typescript', decorators: true },
      transform: { legacyDecorator: true, decoratorMetadata: true },
      target: 'es2022',
    },
    module: { type: 'es6' },
  });
}
