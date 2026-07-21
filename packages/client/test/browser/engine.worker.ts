/**
 * The real engine worker for the browser suite: instantiates the WASM engine
 * over the actual browser seams (against the harness's fake `/routing/v1` mock)
 * and serves the facade protocol. Mirrors the production `engineWorker` wiring,
 * but imports the built `pkg` glue statically instead of dynamically.
 */
import init, {
  Command,
  EngineHandle,
  NodeId,
  NodeKind,
  Permission,
  Staleness,
} from './pkg/cipherbox_wasm.js';
import wasmUrl from './pkg/cipherbox_wasm_bg.wasm?url';

import { EngineHost } from '../../src/worker/engineHost.js';
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import { makeBrowserSeams } from '../../src/worker/browserSeams.js';
import type { EngineWasm } from '../../src/worker/engineWasm.js';

const scope = self as unknown as WorkerScopeLike & { location: { origin: string } };

async function boot(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  const wasm = {
    EngineHandle,
    Command,
    NodeId,
    NodeKind,
    Permission,
    Staleness,
  } as unknown as EngineWasm;
  const { origin } = scope.location;
  const seams = makeBrowserSeams({
    recordEndpoints: [`${origin}/routing`],
    mailboxUrl: `${origin}/mailbox`,
    dbPrefix: `engine-${Date.now()}`,
  });
  const host = new EngineHost(wasm, seams, 'ci');
  serveEngine(scope, host);
}

void boot().catch((error: unknown) => {
  scope.postMessage({
    type: 'fatal',
    error: error instanceof Error ? error.message : String(error),
  });
});
