/**
 * Conformance worker — the engine-worker realm for the browser suite.
 *
 * Instantiates the conformance-featured WASM module and drives one seam's
 * conformance kit (the engine's own Rust kit, re-exported through the
 * crates/wasm bridge) against the real browser seam implementation, using real
 * IndexedDB and OPFS. Posts `{ ok }` on success, `{ ok: false, error }` on a
 * contract violation. Runs in a worker because OPFS synchronous access handles
 * (StagingStore) are worker-only.
 */
import init, {
  runCredentialStoreConformance,
  runFloorStoreConformance,
  runMailboxConformance,
  runRecordTransportConformance,
  runSchedulerConformance,
  runSnapshotCacheConformance,
  runStagingStoreConformance,
  stagingStoreBackings,
} from './pkg/cipherbox_wasm.js';
import wasmUrl from './pkg/cipherbox_wasm_bg.wasm?url';

import {
  ApiMailbox,
  FetchHttp,
  FetchRecordTransport,
  IdbFloorStore,
  IdbSnapshotCache,
  NoopCredentialStore,
  OpfsStagingStore,
  WorkerScheduler,
  toHex,
} from '../../src/seams/index.js';
import { deleteDatabase, openDatabase } from '../../src/seams/idb.js';
import { makeBrowserSeams, reclaimOtherAccountStores } from '../../src/worker/browserSeams.js';
import type { HarnessWorkerScope } from './workerScope.js';

interface SeamOutcome {
  ok: boolean;
  error?: string;
}

const scope = self as unknown as HarnessWorkerScope;

let settled = false;
function post(outcome: SeamOutcome): void {
  if (settled) return;
  settled = true;
  scope.postMessage(outcome);
}

async function clearOpfsDir(name: string): Promise<void> {
  const root = await navigator.storage.getDirectory();
  try {
    await root.removeEntry(name, { recursive: true });
  } catch (error) {
    // Absent directory is the desired empty start state; any other failure is
    // a real cleanup problem and must surface rather than be swallowed.
    if (error instanceof DOMException && error.name === 'NotFoundError') return;
    throw error;
  }
}

/**
 * Replaces the next `createSyncAccessHandle` result with `patch`'s wrapper,
 * then restores the platform method. This is the failed-put kit's fault lever:
 * patching the OPFS boundary leaves the seam itself under test, and a
 * constrained OPFS write is exactly a wrapped handle away — the spec lets it
 * report either a short count or a throw.
 */
function patchNextSyncAccessHandle(
  patch: (handle: FileSystemSyncAccessHandle) => FileSystemSyncAccessHandle
): void {
  const original = FileSystemFileHandle.prototype.createSyncAccessHandle;
  FileSystemFileHandle.prototype.createSyncAccessHandle = async function (
    this: FileSystemFileHandle
  ) {
    FileSystemFileHandle.prototype.createSyncAccessHandle = original;
    return patch(await original.call(this));
  };
}

/** Wraps `handle`, delegating every method of the type except `write`. */
function withWrite(
  handle: FileSystemSyncAccessHandle,
  write: FileSystemSyncAccessHandle['write']
): FileSystemSyncAccessHandle {
  return {
    write,
    read: (buffer, options) => handle.read(buffer, options),
    truncate: (size) => handle.truncate(size),
    getSize: () => handle.getSize(),
    flush: () => handle.flush(),
    close: () => handle.close(),
  };
}

/** Arms the next staged write to move every byte but the last. */
function armShortWrite(): void {
  patchNextSyncAccessHandle((handle) =>
    withWrite(handle, (buffer, options) => {
      const bytes = buffer as Uint8Array;
      return handle.write(bytes.subarray(0, Math.max(0, bytes.byteLength - 1)), options);
    })
  );
}

/** Arms the next staged write to throw the way an over-quota write does. */
function armThrowingWrite(): void {
  patchNextSyncAccessHandle((handle) =>
    withWrite(handle, () => {
      throw new DOMException('simulated quota exhaustion', 'QuotaExceededError');
    })
  );
}

/**
 * Asserts the staged directory holds exactly the records staged under it — an
 * in-flight temp abandoned by a failed put is invisible to `stagedKeys` and
 * `stagedBytesTotal`, so orphan GC could never reclaim it.
 */
async function assertStagedEntryCount(dirName: string, expected: number): Promise<void> {
  const root = await navigator.storage.getDirectory();
  const dir = await root.getDirectoryHandle(dirName);
  const names: string[] = [];
  for await (const name of dir.keys()) names.push(name);
  if (names.length !== expected) {
    throw new Error(
      `staged dir holds ${names.length} entries [${names.join(', ')}], expected ${expected}`
    );
  }
}

/**
 * In-flight write debris — the temp a killed put leaves behind — is not a
 * staged record: it stays out of the orphan-GC enumeration and the staging
 * budget, and a reopened store reclaims it (nothing else can, precisely
 * because it is invisible to both).
 */
async function runStagingDebrisBehavioral(): Promise<void> {
  const name = 'conf-staging-debris';
  const dirName = `${name}-staged`;
  await clearOpfsDir(dirName);

  const store = new OpfsStagingStore(name);
  const key = new Uint8Array([1, 2, 3]);
  await store.putStagedBytes(key, new Uint8Array([9, 9, 9, 9]));

  const dir = await (await navigator.storage.getDirectory()).getDirectoryHandle(dirName);
  const strandedFile = await dir.getFileHandle('.cbtmp.stranded', { create: true });
  const stranded = await strandedFile.createSyncAccessHandle();
  stranded.write(new Uint8Array(64), { at: 0 });
  stranded.flush();
  stranded.close();

  const keys = await store.stagedKeys();
  if (keys.length !== 1 || toHex(keys[0]) !== toHex(key)) {
    throw new Error(`stagedKeys surfaced write debris: [${keys.map(toHex).join(', ')}]`);
  }
  const total = await store.stagedBytesTotal();
  if (total !== 4) {
    throw new Error(`stagedBytesTotal charged write debris: ${total}`);
  }

  await new OpfsStagingStore(name).stagedKeys();
  await assertStagedEntryCount(dirName, 1);
}

/**
 * The staged-record count each kit backing is left holding, keyed by the kit's
 * own backing labels. Anything above these counts is in-flight write debris.
 */
const STAGED_AFTER_KIT: Record<string, number> = {
  ordering: 1,
  'failed-replacement': 1,
  'failed-first-put': 0,
  cleared: 0,
};

/** Stores are per-fault: the kit asserts on leftover staged counts, so another
 * fault's debris would read as this pass's. */
async function runStagingConformance(fault: string, arm: () => void): Promise<void> {
  const storeName = (backing: string): string => `conf-staging-${fault}-${backing}`;
  const backings = stagingStoreBackings();

  for (const backing of backings) {
    await deleteDatabase(storeName(backing));
    await clearOpfsDir(`${storeName(backing)}-staged`);
  }

  await runStagingStoreConformance(
    (backing: string) => Promise.resolve(new OpfsStagingStore(storeName(backing))),
    () => Promise.resolve(arm())
  );

  for (const backing of backings) {
    const staged = STAGED_AFTER_KIT[backing];
    if (staged === undefined) {
      throw new Error(`no staged-record count declared for kit backing "${backing}"`);
    }
    await assertStagedEntryCount(`${storeName(backing)}-staged`, staged);
  }
}

async function runHttpBehavioral(): Promise<void> {
  const http = new FetchHttp();
  const { origin } = scope.location;

  // Non-2xx is a response, not an error.
  const teapot = await http.send({
    method: 'GET',
    url: `${origin}/mock-http/teapot`,
    headers: [],
    body: null,
  });
  if (teapot.status !== 418) {
    throw new Error(`Http: expected status 418, got ${teapot.status}`);
  }

  // Method and body ride through verbatim; headers come back readable.
  const echo = await http.send({
    method: 'POST',
    url: `${origin}/mock-http/echo`,
    headers: [['content-type', 'application/octet-stream']],
    body: new Uint8Array([9, 8, 7]),
  });
  if (echo.status !== 200) {
    throw new Error(`Http: expected status 200, got ${echo.status}`);
  }
  if (echo.body.length !== 3 || echo.body[0] !== 9 || echo.body[2] !== 7) {
    throw new Error('Http: echoed body did not round-trip');
  }
  const method = echo.headers.find(([name]) => name.toLowerCase() === 'x-echo-method');
  if (!method || method[1] !== 'POST') {
    throw new Error('Http: request method was not forwarded');
  }

  // A chunked body with no Content-Length is bounded by the streaming cap.
  const overrun = await http.sendCapped(
    { method: 'GET', url: `${origin}/mock-http/stream`, headers: [], body: null },
    4096
  );
  if (overrun.kind !== 'tooLarge') {
    throw new Error(`Http: expected tooLarge for an uncapped stream, got ${overrun.kind}`);
  }
  if (overrun.limit !== 4096 || overrun.observed <= 4096) {
    throw new Error(`Http: tooLarge reported ${overrun.observed}/${overrun.limit}`);
  }

  // The cap is exclusive: a body exactly at it is admitted.
  const atCap = await http.sendCapped(
    {
      method: 'POST',
      url: `${origin}/mock-http/echo`,
      headers: [],
      body: new Uint8Array([1, 2, 3, 4]),
    },
    4
  );
  if (atCap.kind !== 'response') {
    throw new Error('Http: an at-cap body was not admitted');
  }
  if (atCap.body.length !== 4 || atCap.body[3] !== 4) {
    throw new Error('Http: at-cap body did not round-trip');
  }
}

/**
 * Reclaiming the durable stores of accounts that signed in on this profile
 * before the live one, over real IndexedDB and OPFS. Namespacing made these per
 * account and nothing used to delete them, so an abandoned account's staged op
 * bodies were charged against the live account's staging budget for good.
 */
async function runStoreReclaimBehavioral(): Promise<void> {
  const config = {
    recordEndpoints: [`${scope.location.origin}/routing`],
    apiBaseUrl: `${scope.location.origin}/mock-api/reclaim`,
    // Fresh per run: a previous run's residue would answer for the sweep.
    dbPrefix: `reclaim-${Date.now()}`,
  };
  const live = 'liveaccount';
  const gone = 'goneaccount';
  // A departed account with work still queued: its staged bytes are referenced.
  const busy = 'busyaccount';
  // What a drained departed account gives back: its cache, and its staged bytes.
  const reclaimable = ['snapshot-cache'];
  const kept = ['floors', 'staging'];
  const named = (account: string, suffix: string): string =>
    `${config.dbPrefix}-${account}-${suffix}`;
  const stagedDir = (account: string): string => `${named(account, 'staging')}-staged`;

  // The departed account's residue, seeded and then closed: its stores are shut
  // exactly as an account nobody is signed into leaves them.
  const root = await navigator.storage.getDirectory();
  for (const suffix of [...reclaimable, ...kept]) {
    const db = await openDatabase(named(gone, suffix), 1, (opened) => {
      // The op queue's own store, left empty: a drained queue holds nothing a
      // second account's login must preserve.
      opened.createObjectStore(suffix === 'staging' ? 'ops' : 'records', {
        autoIncrement: suffix === 'staging',
      });
    });
    db.close();
  }
  const debris = await root.getDirectoryHandle(stagedDir(gone), { create: true });
  const staged = await debris.getFileHandle('a1b2', { create: true });
  const handle = await staged.createSyncAccessHandle();
  handle.write(new Uint8Array(4096).fill(9), { at: 0 });
  handle.flush();
  handle.close();

  // A second departed account, seeded through the real seams so the queue the
  // sweep reads is the one production writes — an op still queued, and the
  // staged body it names.
  const busySeams = makeBrowserSeams(config, busy);
  await busySeams.stagingStore.enqueueOp(new Uint8Array([4, 5]));
  await busySeams.stagingStore.putStagedBytes(new Uint8Array([0xab]), new Uint8Array(64).fill(1));

  // The live account's stores, open through the real seams as a running engine
  // holds them.
  const seams = makeBrowserSeams(config, live);
  await seams.floorStore.raiseEpochFloor(new Uint8Array(16), 3);
  await seams.stagingStore.enqueueOp(new Uint8Array([1, 2, 3]));
  await seams.snapshotCache.put(new Uint8Array(8).fill(5), new Uint8Array([7, 7]));

  const reclaimed = (await reclaimOtherAccountStores(config, live)).sort();
  const expected = [...reclaimable.map((suffix) => named(gone, suffix)), stagedDir(gone)].sort();
  if (reclaimed.join('|') !== expected.join('|')) {
    throw new Error(
      `storeReclaim: reclaimed ${reclaimed.join(',')}, expected ${expected.join(',')}`
    );
  }

  const remaining = (await indexedDB.databases()).map((database) => database.name);
  for (const suffix of reclaimable) {
    if (remaining.includes(named(gone, suffix))) {
      throw new Error(`storeReclaim: ${named(gone, suffix)} survived the sweep`);
    }
    if (!remaining.includes(named(live, suffix))) {
      throw new Error(`storeReclaim: ${named(live, suffix)} was reclaimed with the others`);
    }
  }
  // Floors are rollback protection and the op queue is acked work: neither goes.
  for (const suffix of kept) {
    if (!remaining.includes(named(gone, suffix))) {
      throw new Error(`storeReclaim: a departed account lost its ${suffix} store`);
    }
  }
  let busyStagedKept = false;
  for await (const name of root.keys()) {
    if (name === stagedDir(gone)) throw new Error('storeReclaim: staged bytes survived the sweep');
    if (name === stagedDir(busy)) busyStagedKept = true;
  }
  if (!busyStagedKept) {
    throw new Error('storeReclaim: an undrained queue lost its staged bytes');
  }

  // The live account's stores are not merely present but still serving.
  if ((await seams.floorStore.epochFloor(new Uint8Array(16))) !== 3) {
    throw new Error('storeReclaim: the live floor store lost its record');
  }
  if ((await seams.stagingStore.queuedOps()).length !== 1) {
    throw new Error('storeReclaim: the live staging queue lost its op');
  }
  if ((await seams.snapshotCache.get(new Uint8Array(8).fill(5))) === null) {
    throw new Error('storeReclaim: the live snapshot cache lost its entry');
  }
}

async function run(seam: string): Promise<void> {
  await init({ module_or_path: wasmUrl });

  switch (seam) {
    case 'floorStore': {
      const name = 'conf-floors';
      await deleteDatabase(name);
      await runFloorStoreConformance(() => Promise.resolve(new IdbFloorStore(name)));
      return;
    }
    case 'snapshotCache': {
      const name = 'conf-snapshot-cache';
      await deleteDatabase(name);
      await runSnapshotCacheConformance(() => Promise.resolve(new IdbSnapshotCache(name)));
      return;
    }
    case 'stagingStore': {
      // Both OPFS write faults the seam can hit, each against the whole kit.
      // Distinct store names per fault: the kit's handles stay open, and an
      // IndexedDB delete under an open connection blocks rather than clears.
      // The staged-directory counts afterwards are the debris check no kit
      // assertion can make.
      for (const [fault, arm] of [
        ['short-write', armShortWrite],
        ['throwing-write', armThrowingWrite],
      ] as const) {
        await runStagingConformance(fault, arm);
      }
      return;
    }
    case 'credentialStore': {
      await runCredentialStoreConformance(() => Promise.resolve(new NoopCredentialStore()));
      return;
    }
    case 'scheduler': {
      await runSchedulerConformance(new WorkerScheduler());
      return;
    }
    case 'recordTransport': {
      const { origin } = scope.location;
      const transport = new FetchRecordTransport([`${origin}/someguy`, `${origin}/public`]);
      const routingKey = `conf-${Date.now()}-${Math.random().toString(36).slice(2)}`;
      const record = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);
      await runRecordTransportConformance(transport, routingKey, record);
      return;
    }
    case 'mailbox': {
      // A fresh compressed-secp256k1-shaped key per run: it names both the
      // recipient the DTO carries and the mock account whose inbox is polled.
      const ownPublicKey = new Uint8Array(33);
      crypto.getRandomValues(ownPublicKey);
      ownPublicKey[0] = 0x02;
      const { origin } = scope.location;
      const mailbox = new ApiMailbox(new FetchHttp(), `${origin}/mock-api/${toHex(ownPublicKey)}`);
      await runMailboxConformance(mailbox, ownPublicKey);
      return;
    }
    case 'stagingStoreDebris': {
      await runStagingDebrisBehavioral();
      return;
    }
    case 'storeReclaim': {
      await runStoreReclaimBehavioral();
      return;
    }
    case 'http': {
      await runHttpBehavioral();
      return;
    }
    default:
      throw new Error(`unknown seam: ${seam}`);
  }
}

// A failing kit panics inside WASM; the trap surfaces as a worker error or an
// unhandled rejection. Capture both so a failure reports fast instead of the
// harness waiting for a timeout.
scope.addEventListener('error', (event) => post({ ok: false, error: event.message }));
scope.addEventListener('unhandledrejection', (event) =>
  post({ ok: false, error: String(event.reason) })
);

scope.addEventListener('message', (event: MessageEvent<{ seam: string }>) => {
  const { seam } = event.data;
  run(seam)
    .then(() => post({ ok: true }))
    .catch((error: unknown) =>
      post({ ok: false, error: error instanceof Error ? error.message : String(error) })
    );
});
