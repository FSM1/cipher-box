/**
 * Page harness for the Service Worker media-brokerage browser suite. Each
 * Playwright page is a real tab: the Service Worker, its `fetch` interception,
 * the brokered `MessageChannel`, and the response `ReadableStream` are all the
 * browser's own — nothing here is a double.
 */
import { EngineClient } from '../../src/engineClient.js';
import { MediaService } from '../../src/media/service.js';
import { MEDIA_PORT_REQUEST } from '../../src/media/protocol.js';
import type { MediaReader } from '../../src/media/broker.js';
import { hex } from './hexUtil.js';
import { fixtureBuffer, TAB_SEED } from './mediaFixture.js';

/** The dev server transpiles TS per module, so the worker must be a module worker. */
const SW_SCRIPT = '/sw.ts';

/** Bodies above this are asserted by digest; hex would blow up the page bridge. */
const HEX_BODY_LIMIT = 64 * 1024;

/** Which `MediaReader` backs the tab's broker. */
export type MediaReaderKind = 'local' | 'engine';

export interface MediaStartOptions {
  reader: MediaReaderKind;
}

export interface MediaEngineOptions {
  lockName: string;
  channelName: string;
}

/** A page.evaluate-safe response projection; bytes as hex, plus a SHA-256. */
export interface MediaFetchResult {
  status: number;
  headers: Array<[string, string]>;
  byteLength: number;
  digestHex: string;
  /** Empty for bodies over `HEX_BODY_LIMIT`; `digestHex` carries those. */
  bodyHex: string;
  error?: string;
}

declare global {
  interface Window {
    cbMediaEngine(options: MediaEngineOptions): Promise<string>;
    cbMediaStart(options: MediaStartOptions): Promise<boolean>;
    cbMediaAwaitControl(): Promise<boolean>;
    cbMediaTicket(size: number, mimeType: string): string;
    cbMediaFetch(url: string, range: string | null): Promise<MediaFetchResult>;
    cbMediaReaderCalls(): number;
    cbMediaPortRequests(): number;
    cbMediaDispose(): Promise<void>;
  }
}

let service: MediaService | null = null;
let client: EngineClient | null = null;
let readerCalls = 0;
let portRequests = 0;

// A worker that restarted lost its port and must ask for one; counting the asks
// is how the spec distinguishes a re-broker from a port that never died.
navigator.serviceWorker.addEventListener('message', (event: MessageEvent) => {
  if ((event.data as { type?: unknown } | null)?.type === MEDIA_PORT_REQUEST) portRequests += 1;
});

/** Serves the tab's own fixture, counting reads so the spec can see windowing. */
const localReader: MediaReader = {
  downloadRange: (_node, offset, length) => {
    readerCalls += 1;
    return Promise.resolve(fixtureBuffer(offset, length, TAB_SEED));
  },
};

/** Routes every read through this tab's engine client — a follower's wire. */
const engineReader: MediaReader = {
  downloadRange: (node, offset, length) => {
    readerCalls += 1;
    return client!.downloadRange(node, offset, length);
  },
};

window.cbMediaEngine = async ({ lockName, channelName }: MediaEngineOptions): Promise<string> => {
  client = new EngineClient({
    locks: navigator.locks,
    lockName,
    createChannel: () => new BroadcastChannel(channelName),
    spawnWorker: () =>
      new Worker(new URL('./mediaEngine.worker.ts', import.meta.url), {
        type: 'module',
      }),
  });
  // The caller asserts an exact role, so wait for the election rather than
  // guessing at how long a loaded CI machine needs to settle it.
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const role = client?.currentRole() ?? 'none';
    if (role !== 'none') return role;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return 'none';
};

window.cbMediaStart = async ({ reader }: MediaStartOptions): Promise<boolean> => {
  service = new MediaService({
    container: navigator.serviceWorker,
    scriptUrl: SW_SCRIPT,
    scriptType: 'module',
    reader: reader === 'engine' ? engineReader : localReader,
  });
  await service.start();
  // A registration does not control the tab until it claims, and only a
  // controlled tab streams; wait for that before reporting the pipe live.
  await window.cbMediaAwaitControl();
  return service.streaming;
};

/** A registration does not control the tab until it claims; a fetch before that misses the pipe. */
window.cbMediaAwaitControl = async (): Promise<boolean> => {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (navigator.serviceWorker.controller !== null) return true;
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  return false;
};

window.cbMediaTicket = (size: number, mimeType: string): string =>
  service!.createStreamUrl({ node: new Uint8Array(16).fill(3), size, mimeType });

window.cbMediaReaderCalls = (): number => readerCalls;

window.cbMediaPortRequests = (): number => portRequests;

window.cbMediaFetch = async (url: string, range: string | null): Promise<MediaFetchResult> => {
  try {
    const response = await fetch(url, range === null ? {} : { headers: { range } });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return {
      status: response.status,
      headers: [...response.headers].map(([name, value]) => [name, value]),
      byteLength: bytes.byteLength,
      digestHex: hex(digest),
      bodyHex: bytes.byteLength <= HEX_BODY_LIMIT ? hex(bytes) : '',
    };
  } catch (error) {
    return {
      status: 0,
      headers: [],
      byteLength: 0,
      digestHex: '',
      bodyHex: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
};

window.cbMediaDispose = async (): Promise<void> => {
  await service?.dispose();
  service = null;
  await client?.dispose();
  client = null;
  readerCalls = 0;
  portRequests = 0;
  const registrations = await navigator.serviceWorker.getRegistrations();
  await Promise.all(registrations.map((registration) => registration.unregister()));
};

const status = document.getElementById('media-status');
if (status) status.textContent = 'Media brokerage harness ready.';
