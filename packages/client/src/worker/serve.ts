/**
 * The engine worker's protocol server: turns `postMessage` traffic into engine
 * calls and streams events back.
 *
 * Requests are handled concurrently and answered by `id`, so responses may
 * return out of order without confusion — the single engine writer serializes
 * itself below the facade, and the correlation is purely by request id. Steps
 * driving one open write handle are the exception: they run in arrival order
 * (`WriteQueue`). Events ride one ordered pump, so the UI sees them in emission
 * order with no drops.
 */

import { errorMessage } from '../errorMessage.js';
import { WriteQueue } from '../writeQueue.js';
import type { EngineHostLike } from './engineHost.js';
import type { WorkerMessage, WorkerRequest } from './protocol.js';

/** A request driving an already-open write handle, ordered per handle. */
type WriteStep = Extract<WorkerRequest, { type: 'pushChunk' | 'commitWrite' | 'abortWrite' }>;

function isWriteStep(request: WorkerRequest): request is WriteStep {
  const type = request?.type;
  return type === 'pushChunk' || type === 'commitWrite' || type === 'abortWrite';
}

/** The subset of a worker global scope (or `MessagePort`) the server needs. */
export interface WorkerScopeLike {
  postMessage(message: WorkerMessage, transfer?: Transferable[]): void;
  addEventListener(type: 'message', listener: (event: MessageEvent<WorkerRequest>) => void): void;
}

/** The engine's stable error code, when the thrown value carries one. */
function errorCode(error: unknown): string | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

/** Wires `scope` to `host`, then signals readiness. */
export function serveEngine(scope: WorkerScopeLike, host: EngineHostLike): void {
  const post = (message: WorkerMessage): void => scope.postMessage(message);
  // Transfer the plaintext buffer: no byte copy through the boundary.
  const postOwned = (id: number, result: ArrayBuffer): void =>
    scope.postMessage({ type: 'response', id, ok: true, result }, [result]);
  const writes = new WriteQueue();

  const handle = async (request: WorkerRequest): Promise<void> => {
    try {
      switch (request.type) {
        case 'start':
          await host.start(request.secret, request.accountId);
          break;
        case 'command': {
          const result = await host.command(request.command);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'pushChunk':
          await host.pushChunk(request.handle, request.chunk);
          break;
        case 'abortWrite':
          await host.abortWrite(request.handle);
          break;
        case 'beginWrite': {
          const result = await host.beginWrite(request.target, request.size);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'commitWrite': {
          const result = await host.commitWrite(request.handle);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'snapshot': {
          const result = await host.snapshot(request.folder);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'sharing': {
          const result = await host.sharing(request.scope);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'receivedShares': {
          const result = await host.receivedShares();
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'vaultStorage': {
          const result = await host.vaultStorage();
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'authMethods': {
          const result = await host.authMethods();
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'siweChallenge': {
          const result = await host.siweChallenge(request.intent);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'download':
          postOwned(request.id, await host.download(request.node));
          return;
        case 'openContentStream': {
          const result = await host.openContentStream(request.node);
          post({ type: 'response', id: request.id, ok: true, result });
          return;
        }
        case 'readStream':
          postOwned(
            request.id,
            await host.readStream(request.handle, request.offset, request.length)
          );
          return;
        case 'closeStream':
          await host.closeStream(request.handle);
          break;
        default:
          return; // ignore non-request messages (e.g. a bootstrap handshake)
      }
      post({ type: 'response', id: request.id, ok: true });
    } catch (error) {
      post({
        type: 'response',
        id: request.id,
        ok: false,
        error: errorMessage(error),
        code: errorCode(error),
      });
    }
  };

  scope.addEventListener('message', (event) => {
    const request = event.data;
    // Enqueued synchronously, before any await: `WriteQueue` orders a handle's
    // steps by call order. Everything else stays concurrent.
    if (isWriteStep(request)) void writes.run(request.handle, () => handle(request));
    else void handle(request);
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
