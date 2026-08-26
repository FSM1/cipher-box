/**
 * The real engine worker for the browser suite: instantiates the WASM engine
 * over the actual browser seams (against the harness's fake `/routing/v1` mock)
 * and serves the facade protocol. Mirrors the production `engineWorker` wiring,
 * but imports the built `pkg` glue statically instead of dynamically.
 */
// Namespace import, not named bindings: the host needs every binding `EngineWasm`
// declares, and a hand-listed set silently goes stale when one is added.
import init, * as glue from './pkg/cipherbox_wasm.js';
import wasmUrl from './pkg/cipherbox_wasm_bg.wasm?url';

import { EngineHost } from '../../src/worker/engineHost.js';
import { serveEngine, type WorkerScopeLike } from '../../src/worker/serve.js';
import { makeBrowserSeams } from '../../src/worker/browserSeams.js';
import type { EngineWasm } from '../../src/worker/engineWasm.js';

const scope = self as unknown as WorkerScopeLike & { location: { origin: string } };

async function boot(): Promise<void> {
  await init({ module_or_path: wasmUrl });
  const wasm = glue as unknown as EngineWasm;
  const { origin } = scope.location;
  const apiBaseUrl = `${origin}/mock-api/engine`;
  const seamConfig = {
    recordEndpoints: [`${origin}/routing`],
    dbPrefix: `engine-${Date.now()}`,
  };
  const host = new EngineHost(wasm, (accountId) => makeBrowserSeams(seamConfig, accountId), {
    apiBaseUrl,
    profile: 'ci',
  });
  serveEngine(scope, host);
}

void boot().catch((error: unknown) => {
  scope.postMessage({
    type: 'fatal',
    error: error instanceof Error ? error.message : String(error),
  });
});
