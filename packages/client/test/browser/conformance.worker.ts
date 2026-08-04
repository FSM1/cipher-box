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
import { deleteDatabase } from '../../src/seams/idb.js';
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
      const name = 'conf-staging';
      await deleteDatabase(name);
      await clearOpfsDir(`${name}-staged`);
      await runStagingStoreConformance(() => Promise.resolve(new OpfsStagingStore(name)));
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
