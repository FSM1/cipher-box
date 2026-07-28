// Web3Auth and its tkey dependencies read `process` and `Buffer` off the global
// scope, which browsers do not provide. Imported first in `main.tsx`.
// @ts-expect-error - the process browser shim ships no type declarations
import processShim from 'process/browser';
import { Buffer as BufferShim } from 'buffer';

declare global {
  var process: typeof processShim;
}

globalThis.process = processShim;
globalThis.Buffer = BufferShim;
