/**
 * Page harness for the browser seam conformance suite.
 *
 * Exposes `window.runSeam(name)`, which Playwright calls per seam. Each call
 * spawns a fresh module worker (the "engine worker realm" — OPFS synchronous
 * access handles require a worker), runs one seam's conformance kit there, and
 * resolves with the outcome. A fresh worker per seam keeps a failing kit's
 * WASM trap from poisoning later kits.
 */

export interface SeamOutcome {
  ok: boolean;
  error?: string;
}

declare global {
  interface Window {
    runSeam(seam: string): Promise<SeamOutcome>;
  }
}

window.runSeam = (seam: string): Promise<SeamOutcome> =>
  new Promise<SeamOutcome>((resolve) => {
    const worker = new Worker(new URL('./conformance.worker.ts', import.meta.url), {
      type: 'module',
    });

    let settled = false;
    const finish = (outcome: SeamOutcome): void => {
      if (settled) return;
      settled = true;
      worker.terminate();
      resolve(outcome);
    };

    worker.addEventListener('message', (event: MessageEvent<SeamOutcome>) => finish(event.data));
    worker.addEventListener('error', (event: ErrorEvent) =>
      finish({ ok: false, error: event.message || 'worker error' })
    );

    worker.postMessage({ seam });
  });

const status = document.getElementById('status');
if (status) {
  status.textContent = 'Browser seam conformance harness ready.';
}
