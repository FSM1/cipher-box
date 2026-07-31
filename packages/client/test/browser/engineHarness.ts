/**
 * Page harness for the engine-worker suite. Exposes `window` entry points the
 * Playwright spec calls; each drives the real `LocalTransport` + `EngineFacade`
 * against a worker (the real WASM engine, or the protocol fake) and returns a
 * plain result the spec asserts on.
 */
import { EngineFacade } from '../../src/facade.js';
import { LocalTransport } from '../../src/transport.js';
import type { EventDescriptor, PendingClass } from '../../src/worker/protocol.js';
import { hex } from './hexUtil.js';

export interface RealEngineResult {
  beforeStart: string;
  startOk: boolean;
  secretDetached: boolean;
  afterStart: string;
  afterLogout: string;
}

export interface BoundaryOutcome {
  ok: boolean;
  error?: string;
}

/** A page.evaluate-safe projection of the snapshot read surface. */
export interface SnapshotSuiteResult {
  rootEchoed: boolean;
  children: Array<{
    name: string;
    kind: string;
    pending: PendingClass;
    deadLetter: boolean;
    sizeNull: boolean;
    mtimeNull: boolean;
  }>;
  nestedAncestors: Array<{ idHex: string; name: string }>;
  rootHex: string;
  /** The folder a rootless `snapshot(null)` answered with. */
  rootlessFolderHex: string;
  unknownError: string;
  unknownCode: string;
  downloadError: string;
  downloadCode: string;
}

declare global {
  interface Window {
    runRealEngine(): Promise<RealEngineResult>;
    runSnapshotSuite(): Promise<SnapshotSuiteResult>;
    runFakeOutOfOrder(): Promise<{ order: string[] }>;
    runFakeEvents(): Promise<{ events: number[] }>;
    runBoundary(name: string): Promise<BoundaryOutcome>;
  }
}

function realWorker(): Worker {
  return new Worker(new URL('./engine.worker.ts', import.meta.url), { type: 'module' });
}

function fakeWorker(): Worker {
  return new Worker(new URL('./fakeEngine.worker.ts', import.meta.url), { type: 'module' });
}

function facadeOver(worker: Worker): { facade: EngineFacade; transport: LocalTransport } {
  const transport = new LocalTransport(worker);
  return { facade: new EngineFacade(transport), transport };
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The engine's stable error code as crossed on the rejection, '' if absent. */
function code(error: unknown): string {
  const value = (error as { code?: unknown } | null)?.code;
  return typeof value === 'string' ? value : '';
}

window.runRealEngine = async (): Promise<RealEngineResult> => {
  const { facade } = facadeOver(realWorker());
  const result: RealEngineResult = {
    beforeStart: '',
    startOk: false,
    secretDetached: false,
    afterStart: '',
    afterLogout: '',
  };

  // A command before start is rejected as "not started" — the gate proving the
  // engine's start lifecycle is enforced across the boundary.
  await facade.manualRefresh().catch((error: unknown) => {
    result.beforeStart = message(error);
  });

  // A valid secp256k1 identity scalar: 32 bytes, non-zero, well below the curve order n.
  const secret = new Uint8Array(32).fill(1).buffer;
  await facade.start(secret);
  result.startOk = true;
  result.secretDetached = secret.byteLength === 0;

  // Post-start, the same command reaches a started engine (its pipeline is not
  // yet wired, so it answers "not implemented" — not "not started").
  await facade.manualRefresh().catch((error: unknown) => {
    result.afterStart = message(error);
  });

  await facade.logout();

  // After teardown the transport is closed and rejects further work.
  await facade.manualRefresh().catch((error: unknown) => {
    result.afterLogout = message(error);
  });

  return result;
};

window.runSnapshotSuite = async (): Promise<SnapshotSuiteResult> => {
  const { facade, transport } = facadeOver(realWorker());
  try {
    await facade.start(new Uint8Array(32).fill(1).buffer);

    // Metadata-only creates: pending overlay entries with no content plane.
    const root = new Uint8Array(16);
    await facade.create(root, 'docs', 'folder');
    await facade.create(root, 'pending.txt', 'file');

    const view = await facade.snapshot(root);
    const docs = view.children.find((child) => child.name === 'docs');
    const file = view.children.find((child) => child.name === 'pending.txt');
    if (!docs || !file) throw new Error('created children missing from the root snapshot');

    const nested = await facade.snapshot(docs.id);
    // No folder named: the engine answers with its own current root.
    const rootless = await facade.snapshot(null);

    let unknownError = '';
    let unknownCode = '';
    await facade.snapshot(new Uint8Array(16).fill(0x5a)).catch((error: unknown) => {
      unknownError = message(error);
      unknownCode = code(error);
    });

    let downloadError = '';
    let downloadCode = '';
    await facade.download(file.id).catch((error: unknown) => {
      downloadError = message(error);
      downloadCode = code(error);
    });

    return {
      rootEchoed: hex(view.folder) === hex(view.root) && hex(view.root) === hex(root),
      children: view.children.map((child) => ({
        name: child.name,
        kind: child.kind,
        pending: child.pending,
        deadLetter: child.deadLetter,
        sizeNull: child.size === null,
        mtimeNull: child.mtime === null,
      })),
      nestedAncestors: nested.ancestors.map((ancestor) => ({
        idHex: hex(ancestor.id),
        name: ancestor.name,
      })),
      rootHex: hex(view.root),
      rootlessFolderHex: hex(rootless.folder),
      unknownError,
      unknownCode,
      downloadError,
      downloadCode,
    };
  } finally {
    transport.close();
  }
};

window.runFakeOutOfOrder = async (): Promise<{ order: string[] }> => {
  const { facade, transport } = facadeOver(fakeWorker());
  const order: string[] = [];
  const first = facade.delete(new Uint8Array(16)).then(() => order.push('first'));
  const second = facade.delete(new Uint8Array(16)).then(() => order.push('second'));
  await Promise.all([first, second]);
  transport.close();
  return { order };
};

window.runFakeEvents = async (): Promise<{ events: number[] }> => {
  const { facade, transport } = facadeOver(fakeWorker());
  const events: number[] = [];
  const done = new Promise<void>((resolve) => {
    facade.subscribe((event: EventDescriptor) => {
      if (event.kind !== 'deadLetter') return;
      events.push(Number(event.opId));
      if (events.length === 10) resolve();
    });
  });
  await facade.manualRefresh();
  await done;
  transport.close();
  return { events };
};

window.runBoundary = (name: string): Promise<BoundaryOutcome> =>
  new Promise<BoundaryOutcome>((resolve) => {
    const worker = new Worker(new URL('./boundary.worker.ts', import.meta.url), { type: 'module' });
    let settled = false;
    const finish = (outcome: BoundaryOutcome): void => {
      if (settled) return;
      settled = true;
      worker.terminate();
      resolve(outcome);
    };
    worker.addEventListener('message', (event: MessageEvent<BoundaryOutcome>) =>
      finish(event.data)
    );
    worker.addEventListener('error', (event: ErrorEvent) =>
      finish({ ok: false, error: event.message || 'worker error' })
    );
    worker.postMessage({ name });
  });

const status = document.getElementById('engine-status');
if (status) status.textContent = 'Engine worker harness ready.';
