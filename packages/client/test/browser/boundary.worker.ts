/**
 * Transfer/boundary-hygiene checks (blueprint/web-client.md "Boundary
 * hygiene"), run in a worker realm (OPFS is worker-only):
 *
 * - `bigint`: the facade's `u64`→`bigint` boundary round-trips a value beyond
 *   `Number.MAX_SAFE_INTEGER` intact, through the real wasm-bindgen `Event`.
 * - `stagingDetachment` (#717): a WASM-backed byte view handed to a seam is
 *   copied synchronously at entry, so detaching it across the seam's awaits
 *   cannot corrupt or truncate the stored bytes. The test grows a
 *   `WebAssembly.Memory` (detaching the view) right after the call, before its
 *   awaits resolve; a copy-after-await implementation would write a detached
 *   view and fail.
 */
import init, { deadLetterEvent } from './pkg/cipherbox_wasm.js';
import wasmUrl from './pkg/cipherbox_wasm_bg.wasm?url';

import { OpfsStagingStore } from '../../src/seams/index.js';

interface Outcome {
  ok: boolean;
  error?: string;
}

const scope = self as unknown as DedicatedWorkerGlobalScope;

async function clearOpfsDir(name: string): Promise<void> {
  const root = await navigator.storage.getDirectory();
  try {
    await root.removeEntry(name, { recursive: true });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') return;
    throw error;
  }
}

async function runBigint(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  const huge = 9_007_199_254_740_993n; // 2^53 + 1 — not representable as a JS number
  const event = deadLetterEvent(huge);
  if (event.kind !== 'deadLetter') throw new Error(`kind ${event.kind}`);
  if (typeof event.opId !== 'bigint') throw new Error(`opId type ${typeof event.opId}`);
  if (event.opId !== huge) throw new Error(`opId ${event.opId} !== ${huge}`);
}

async function runStagingDetachment(): Promise<void> {
  const dirName = `boundary-staging-${Date.now()}`;
  await clearOpfsDir(`${dirName}-staged`);
  const store = new OpfsStagingStore(dirName);

  const memory = new WebAssembly.Memory({ initial: 1 });
  const view = new Uint8Array(memory.buffer, 0, 32);
  for (let i = 0; i < view.length; i += 1) view[i] = (i * 7 + 1) & 0xff;
  const expected = view.slice();
  const key = new Uint8Array([0xab, 0xcd]);

  // Start the write, then detach the source view before its awaits resolve.
  const writing = store.putStagedBytes(key, view);
  memory.grow(1); // detaches memory.buffer → `view` is now zero-length
  if (view.byteLength !== 0) throw new Error('precondition: view was not detached by grow');
  await writing;

  const stored = await store.stagedBytes(key);
  if (!stored || stored.length !== expected.length) {
    throw new Error(`stored length ${stored?.length ?? 'null'} != ${expected.length}`);
  }
  for (let i = 0; i < expected.length; i += 1) {
    if (stored[i] !== expected[i]) throw new Error(`byte ${i}: ${stored[i]} != ${expected[i]}`);
  }
}

async function run(name: string): Promise<void> {
  switch (name) {
    case 'bigint':
      return runBigint();
    case 'stagingDetachment':
      return runStagingDetachment();
    default:
      throw new Error(`unknown boundary check: ${name}`);
  }
}

scope.addEventListener('message', (event: MessageEvent<{ name: string }>) => {
  run(event.data.name)
    .then(() => scope.postMessage({ ok: true } satisfies Outcome))
    .catch((error: unknown) =>
      scope.postMessage({
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      } satisfies Outcome)
    );
});
