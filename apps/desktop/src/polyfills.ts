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

// Stubbed to throw so the Core Kit scalar cannot rest on disk before a
// keychain-backed CredentialStore seam exists (blueprint/desktop.md, "Engine wiring").
const AT_REST = ['localStorage', 'sessionStorage', 'indexedDB'] as const;

for (const store of AT_REST) {
  Object.defineProperty(globalThis, store, {
    configurable: true,
    get(): never {
      throw new Error(`${store} holds nothing in the CipherBox shell`);
    },
  });
}
