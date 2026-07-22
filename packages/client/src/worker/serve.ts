/**
 * The engine worker's protocol server: turns `postMessage` traffic into engine
 * calls and streams events back.
 *
 * Requests are handled concurrently and answered by `id`, so responses may
 * return out of order without confusion — the single engine writer serializes
 * itself below the facade, and the correlation is purely by request id. Events
 * ride one ordered pump, so the UI sees them in emission order with no drops.
 */

import type { EngineHostLike } from './engineHost.js';
import type { WorkerMessage, WorkerRequest } from './protocol.js';

/** The subset of a worker global scope (or `MessagePort`) the server needs. */
export interface WorkerScopeLike {
  postMessage(message: WorkerMessage): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** Wires `scope` to `host`, then signals readiness. */
export function serveEngine(scope: WorkerScopeLike, host: EngineHostLike): void {
  const post = (message: WorkerMessage): void => scope.postMessage(message);

  const handle = async (request: WorkerRequest): Promise<void> => {
    try {
      if (request.type === 'start') {
        await host.start(request.secret);
      } else if (request.type === 'command') {
        await host.command(request.command);
      } else {
        return; // ignore non-request messages (e.g. a bootstrap handshake)
      }
      post({ type: 'response', id: request.id, ok: true });
    } catch (error) {
      post({ type: 'response', id: request.id, ok: false, error: errorMessage(error) });
    }
  };

  scope.addEventListener('message', (event) => {
    void handle(event.data);
  });

  void (async () => {
    try {
      for (;;) {
        const event = await host.nextEvent();
        if (event === null) return;
        post({ type: 'event', event });
      }
    } catch (error) {
      post({ type: 'fatal', error: errorMessage(error) });
    }
  })();

  post({ type: 'ready' });
}
