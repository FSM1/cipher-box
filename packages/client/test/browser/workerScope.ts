/**
 * The subset of `DedicatedWorkerGlobalScope` the harness workers drive.
 *
 * Declared structurally rather than pulled from `lib.webworker`, whose globals
 * collide with the `DOM` lib the seams compile against — the same shape
 * `WorkerScopeLike` takes in `src/worker/serve.ts`.
 */
export interface HarnessWorkerScope {
  readonly location: { readonly origin: string };
  postMessage(message: unknown): void;
  addEventListener(type: 'message', listener: (event: MessageEvent) => void): void;
  addEventListener(type: 'error', listener: (event: { message: string }) => void): void;
  addEventListener(
    type: 'unhandledrejection',
    listener: (event: { reason: unknown }) => void
  ): void;
}
