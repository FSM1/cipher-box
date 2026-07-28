import { EngineClient } from '@cipherbox/client';
import { engineBootstrapConfig } from './config';
import { spawnEngineWorker } from './spawnEngineWorker';

/**
 * Wires this tab's engine client to the browser: `navigator.locks` drives the
 * leader election, and the leader spawns the Vite-bundled engine worker
 * (blueprint/web-client.md "Engine hosting and tab leadership").
 */
export function createEngineClient(): EngineClient {
  const bootstrap = engineBootstrapConfig(import.meta.env);
  return new EngineClient({
    locks: navigator.locks,
    spawnWorker: () => spawnEngineWorker(bootstrap),
    onError: (error) => console.error('[engine]', error.message),
  });
}
