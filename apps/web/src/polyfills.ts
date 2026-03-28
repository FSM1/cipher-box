// @ts-expect-error - process polyfill has no types
import process from 'process/browser';
import { Buffer } from 'buffer';

// Phase 28: These globalThis/window augmentations are acceptable polyfill shims.
// Web3Auth and dependent libraries expect process and Buffer on the global scope.
declare global {
  var process: typeof process;

  var Buffer: typeof Buffer;
}

globalThis.process = process;
globalThis.Buffer = Buffer;

export {};
