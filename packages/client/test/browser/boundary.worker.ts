/**
 * Transfer/boundary-hygiene checks (blueprint/web-client.md "Boundary
 * hygiene"), run in a worker realm (OPFS is worker-only):
 *
 * - `events`: an engine event reaches JS as the generated `Event` type names
 *   it — a `u64` beyond `Number.MAX_SAFE_INTEGER` as an exact `bigint`, bytes
 *   as a `Uint8Array`, an absent field as `null`, a nested struct as numbers,
 *   an enum as its name.
 * - `stagingDetachment`: a WASM-backed byte *value* handed to a seam is
 *   copied synchronously at entry, so detaching it across the seam's awaits
 *   cannot corrupt or truncate the stored bytes. The test grows a
 *   `WebAssembly.Memory` (detaching the view) right after the call, before its
 *   awaits resolve; a copy-after-await implementation would write a detached
 *   view and fail.
 * - `stagingKeyDetachment` / `snapshotKeyDetachment` / `floorKeyDetachment`: the
 *   *key* view is likewise encoded synchronously at entry. A key hexed after the
 *   await would read a detached view as '' and store the entry under the wrong
 *   name, so the read-back under the real key here would miss — the fix stores
 *   it correctly.
 * - `identityFingerprint`: the wasm export answers the core KAT
 *   (`crates/core/kat/vectors/contact/fingerprint.json`) and refuses a key that
 *   is not 33 bytes.
 */
import init, { identityFingerprint, sampleEvents, type Event } from './pkg/cipherbox_wasm.js';
import wasmUrl from './pkg/cipherbox_wasm_bg.wasm?url';
import fingerprintVectors from '../../../../crates/core/kat/vectors/contact/fingerprint.json?raw';

import { IdbFloorStore, IdbSnapshotCache, OpfsStagingStore } from '../../src/seams/index.js';
import { deleteDatabase } from '../../src/seams/idb.js';
import { unhex } from './hexUtil.js';
import type { HarnessWorkerScope } from './workerScope.js';

interface Outcome {
  ok: boolean;
  error?: string;
}

const scope = self as unknown as HarnessWorkerScope;

async function clearOpfsDir(name: string): Promise<void> {
  const root = await navigator.storage.getDirectory();
  try {
    await root.removeEntry(name, { recursive: true });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'NotFoundError') return;
    throw error;
  }
}

function expectBytes(value: unknown, expected: number[], what: string): void {
  if (!(value instanceof Uint8Array)) throw new Error(`${what} is not a Uint8Array`);
  if (value.join() !== expected.join()) throw new Error(`${what} ${value.join()}`);
}

async function runEvents(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  const huge = 9_007_199_254_740_993n; // 2^53 + 1 — not representable as a JS number
  const [dead, upload, download, withheld, stale, snapshot, sweep]: Event[] = sampleEvents(huge);

  if (dead?.kind !== 'deadLetter') throw new Error(`kind ${dead?.kind}`);
  if (typeof dead.opId !== 'bigint') throw new Error(`opId type ${typeof dead.opId}`);
  if (dead.opId !== huge) throw new Error(`opId ${dead.opId} !== ${huge}`);
  if (dead.reason !== 'targetIsScopeRoot') throw new Error(`reason ${dead.reason}`);
  expectBytes(dead.target, Array(16).fill(9), 'dead letter target');

  if (upload?.kind !== 'opProgress') throw new Error(`kind ${upload?.kind}`);
  if (upload.opId !== huge) throw new Error(`progress opId ${upload.opId}`);
  expectBytes(upload.node, Array(16).fill(7), 'node');
  if (upload.phase !== 'uploadProgress') throw new Error(`phase ${upload.phase}`);
  if (upload.progress?.confirmed !== 2 || upload.progress.total !== 5) {
    throw new Error(`progress ${JSON.stringify(upload.progress)}`);
  }
  if (upload.error !== 'unavailable') throw new Error(`error ${upload.error}`);

  if (download?.kind !== 'opProgress') throw new Error(`kind ${download?.kind}`);
  for (const [name, value] of Object.entries({
    opId: download.opId,
    progress: download.progress,
    error: download.error,
  })) {
    if (value !== null) throw new Error(`absent ${name} is ${String(value)}, not null`);
  }

  if (withheld?.kind !== 'withheldUpdateEscalation') throw new Error(`kind ${withheld?.kind}`);
  expectBytes(withheld.ipnsName, [9, 8, 7], 'ipnsName');
  if (stale?.kind !== 'stalenessChanged' || stale.staleness !== 'offline') {
    throw new Error(`staleness ${JSON.stringify(stale)}`);
  }
  if (snapshot?.kind !== 'snapshotUpdated' || Object.keys(snapshot).length !== 1) {
    throw new Error(`snapshot ${JSON.stringify(snapshot)}`);
  }

  if (sweep?.kind !== 'sweepConvergence') throw new Error(`kind ${sweep?.kind}`);
  if (sweep.cutAt !== huge) throw new Error(`cutAt ${String(sweep.cutAt)}`);
  if (sweep.at !== huge) throw new Error(`at ${String(sweep.at)}`);
  if (sweep.lastResealAt !== null) throw new Error(`lastResealAt ${String(sweep.lastResealAt)}`);
}

interface FingerprintVector {
  name: string;
  identityPk: string;
  fingerprint: string;
}

const FINGERPRINT_KAT = JSON.parse(fingerprintVectors) as FingerprintVector[];

async function runIdentityFingerprint(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  if (FINGERPRINT_KAT.length === 0) throw new Error('no fingerprint vectors');
  for (const { name, identityPk, fingerprint } of FINGERPRINT_KAT) {
    const got = identityFingerprint(unhex(identityPk));
    if (got !== fingerprint) throw new Error(`fingerprint ${name}: ${got} != ${fingerprint}`);
  }
  let refused = false;
  try {
    identityFingerprint(new Uint8Array(32).fill(2));
  } catch {
    refused = true;
  }
  if (!refused) throw new Error('a 32-byte identity key was fingerprinted');
}

async function runStagingDetachment(): Promise<void> {
  const dirName = `boundary-staging-${Date.now()}-${crypto.randomUUID()}`;
  await clearOpfsDir(`${dirName}-staged`);
  const store = new OpfsStagingStore(dirName);
  try {
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
  } finally {
    await clearOpfsDir(`${dirName}-staged`);
  }
}

async function runStagingKeyDetachment(): Promise<void> {
  const dirName = `boundary-staging-key-${Date.now()}-${crypto.randomUUID()}`;
  await clearOpfsDir(`${dirName}-staged`);
  const store = new OpfsStagingStore(dirName);
  try {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const keyView = new Uint8Array(memory.buffer, 0, 8);
    for (let i = 0; i < keyView.length; i += 1) keyView[i] = (i * 13 + 3) & 0xff;
    const expectedKey = keyView.slice();
    const bytes = new Uint8Array([1, 2, 3, 4]);

    // Start the write, then detach the KEY view before its awaits resolve.
    const writing = store.putStagedBytes(keyView, bytes);
    memory.grow(1); // detaches memory.buffer → `keyView` is now zero-length
    if (keyView.byteLength !== 0) {
      throw new Error('precondition: key view was not detached by grow');
    }
    await writing;

    // Read back under the real key. A key hexed after the await would be '',
    // storing the entry under the wrong name and missing here.
    const stored = await store.stagedBytes(expectedKey);
    if (!stored || stored.length !== bytes.length) {
      throw new Error(`stored length ${stored?.length ?? 'null'} != ${bytes.length}`);
    }
    for (let i = 0; i < bytes.length; i += 1) {
      if (stored[i] !== bytes[i]) throw new Error(`byte ${i}: ${stored[i]} != ${bytes[i]}`);
    }
  } finally {
    await clearOpfsDir(`${dirName}-staged`);
  }
}

async function runSnapshotKeyDetachment(): Promise<void> {
  const cache = new IdbSnapshotCache(`boundary-snapshot-key-${Date.now()}-${crypto.randomUUID()}`);
  try {
    const memory = new WebAssembly.Memory({ initial: 1 });
    const keyView = new Uint8Array(memory.buffer, 0, 8);
    for (let i = 0; i < keyView.length; i += 1) keyView[i] = (i * 5 + 2) & 0xff;
    const expectedKey = keyView.slice();
    const value = new Uint8Array([9, 8, 7, 6]);

    // Start the put, then detach the KEY view before its await resolves.
    const writing = cache.put(keyView, value);
    memory.grow(1); // detaches memory.buffer → `keyView` is now zero-length
    if (keyView.byteLength !== 0) {
      throw new Error('precondition: key view was not detached by grow');
    }
    await writing;

    const stored = await cache.get(expectedKey);
    if (!stored || stored.length !== value.length) {
      throw new Error(`stored length ${stored?.length ?? 'null'} != ${value.length}`);
    }
    for (let i = 0; i < value.length; i += 1) {
      if (stored[i] !== value[i]) throw new Error(`byte ${i}: ${stored[i]} != ${value[i]}`);
    }
  } finally {
    await cache.clear();
  }
}

async function runFloorKeyDetachment(): Promise<void> {
  const dbName = `boundary-floors-${Date.now()}-${crypto.randomUUID()}`;
  // Start from an empty backing; the per-run name keeps runs independent, and
  // the store holds its connection open for the life of the worker.
  await deleteDatabase(dbName);
  const store = new IdbFloorStore(dbName);
  const memory = new WebAssembly.Memory({ initial: 1 });
  const keyView = new Uint8Array(memory.buffer, 0, 8);
  for (let i = 0; i < keyView.length; i += 1) keyView[i] = (i * 11 + 5) & 0xff;
  const expectedKey = keyView.slice();

  // Start the raise, then detach the KEY view before its awaits resolve.
  const raising = store.raiseEpochFloor(keyView, 7);
  memory.grow(1); // detaches memory.buffer → `keyView` is now zero-length
  if (keyView.byteLength !== 0) {
    throw new Error('precondition: key view was not detached by grow');
  }
  if ((await raising) !== 7) throw new Error('raiseEpochFloor did not return the raised floor');

  // Read back under the real key. A key hexed after the await would be '',
  // raising the floor under the wrong scope and missing here.
  const stored = await store.epochFloor(expectedKey);
  if (stored !== 7) throw new Error(`epochFloor ${stored} != 7`);

  // The read path hexes at entry too: detaching across its await must not turn
  // a real floor into a "no floor" answer.
  const readKey = new Uint8Array(memory.buffer, 0, 8);
  readKey.set(expectedKey);
  const reading = store.epochFloor(readKey);
  memory.grow(1);
  if (readKey.byteLength !== 0) {
    throw new Error('precondition: read key view was not detached by grow');
  }
  const reread = await reading;
  if (reread !== 7) throw new Error(`epochFloor across a detached read key ${reread} != 7`);
}

async function run(name: string): Promise<void> {
  switch (name) {
    case 'events':
      return runEvents();
    case 'stagingDetachment':
      return runStagingDetachment();
    case 'stagingKeyDetachment':
      return runStagingKeyDetachment();
    case 'snapshotKeyDetachment':
      return runSnapshotKeyDetachment();
    case 'floorKeyDetachment':
      return runFloorKeyDetachment();
    case 'identityFingerprint':
      return runIdentityFingerprint();
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
