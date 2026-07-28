/**
 * The engine worker entry Vite bundles. `packages/client` owns the worker body;
 * this module exists only to give the bundler a source entry to point
 * `new Worker(new URL('./engineWorker.ts', import.meta.url))` at.
 */
import '@cipherbox/client/worker';
