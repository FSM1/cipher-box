/**
 * The browser suite's one Service Worker bootstrap. Both the media pipe and a
 * follower's read port need a worker that controls the tab, so registration and
 * the wait for control live here rather than in each page harness.
 */

/** The dev server transpiles TS per module, so the worker must be a module worker. */
export const SW_SCRIPT = '/sw.ts';

const CONTROL_TIMEOUT_MS = 10_000;

/** Resolves once this tab's own fetches and messages reach the worker. */
export async function awaitServiceWorkerControl(): Promise<boolean> {
  await navigator.serviceWorker.register(SW_SCRIPT, { scope: '/', type: 'module' });
  await navigator.serviceWorker.ready;
  if (navigator.serviceWorker.controller !== null) return true;
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), CONTROL_TIMEOUT_MS);
    navigator.serviceWorker.addEventListener(
      'controllerchange',
      () => {
        clearTimeout(timer);
        resolve(true);
      },
      { once: true }
    );
  });
}
