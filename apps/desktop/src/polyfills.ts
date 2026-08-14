// Web3Auth and its tkey dependencies read `process` and `Buffer` off the global
// scope, which this webview does not provide. Imported first in `main.ts`.
// @ts-expect-error - the process browser shim ships no type declarations
import processShim from 'process/browser';
import { Buffer as BufferShim } from 'buffer';

declare global {
  var process: typeof processShim;
}

globalThis.process = processShim;
globalThis.Buffer = BufferShim;
