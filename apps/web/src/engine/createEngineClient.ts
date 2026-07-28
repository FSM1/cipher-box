import { EngineClient, spawnEngineWorker } from '@cipherbox/client';
import { engineHostConfig } from './config';

/**
 * Wires this tab's engine client to the browser: `navigator.locks` drives the
 * leader election, and the leader hosts the engine worker
 * (blueprint/web-client.md "Engine hosting and tab leadership").
 */
export function createEngineClient(): EngineClient {
  const host = engineHostConfig(import.meta.env);
  return new EngineClient({
    locks: navigator.locks,
    spawnWorker: () => spawnEngineWorker(host),
    onError: (error) => console.error('[engine]', error.message),
  });
}
