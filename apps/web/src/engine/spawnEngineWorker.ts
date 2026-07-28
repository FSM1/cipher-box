import type { EngineWorkerBootstrap } from '@cipherbox/client/worker';
import type { EngineBootstrapConfig } from './config';

/** Creates the module worker; injectable so tests never need a real `Worker`. */
export type EngineWorkerFactory = () => Worker;

const spawnModuleWorker: EngineWorkerFactory = () =>
  new Worker(new URL('./engineWorker.ts', import.meta.url), { type: 'module' });

/**
 * Spawns the engine worker and completes its one-shot bootstrap handshake. The
 * worker ignores every other message until it has been bootstrapped, so the
 * handshake must be posted before the transport drives it.
 */
export function spawnEngineWorker(
  config: EngineBootstrapConfig,
  createWorker: EngineWorkerFactory = spawnModuleWorker
): Worker {
  const worker = createWorker();
  const bootstrap: EngineWorkerBootstrap = { type: 'bootstrap', ...config };
  worker.postMessage(bootstrap);
  return worker;
}
