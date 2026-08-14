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

/**
 * The web stores a Tauri webview persists to the app data dir.
 *
 * The Core Kit scalar both addresses and decrypts the Web3Auth record holding
 * the login secret, and nothing on this host may hold it at rest until a
 * keychain-backed CredentialStore seam exists (blueprint/desktop.md, "Engine
 * wiring"). Stubbed to throw so a dependency that reaches for one fails where a
 * member can see it, rather than writing a factor share to disk.
 */
const AT_REST = ['localStorage', 'sessionStorage', 'indexedDB'] as const;

for (const store of AT_REST) {
  Object.defineProperty(globalThis, store, {
    configurable: true,
    get(): never {
      throw new Error(`${store} holds nothing in the CipherBox shell`);
    },
  });
}
