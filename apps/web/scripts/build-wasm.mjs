// Builds the production wasm-bindgen ES module the engine worker loads
// (blueprint/web-client.md "WASM packaging"). Runs before `vite build`/`vite`
// (see the `build:wasm` script); Vite fingerprints the emitted files through the
// `?url` imports in src/engine/createEngineClient.ts. Release profile, and
// without the `conformance` feature, so the engine test kit never reaches the
// shipped artifact. Cargo is the freshness oracle — a re-run with unchanged
// crates is a no-op.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const here = import.meta.dirname;
const repoRoot = resolve(here, '../../..');
const outDir = resolve(here, '../src/wasm');
const wasmArtifact = resolve(repoRoot, 'target/wasm32-unknown-unknown/release/cipherbox_wasm.wasm');

const run = (command, args) => execFileSync(command, args, { cwd: repoRoot, stdio: 'inherit' });

run('cargo', ['build', '-p', 'cipherbox-wasm', '--release', '--target', 'wasm32-unknown-unknown']);

run('wasm-bindgen', [
  '--target',
  'web',
  '--out-dir',
  outDir,
  '--out-name',
  'cipherbox_wasm',
  wasmArtifact,
]);

console.log(`Engine WASM + bindings written to ${outDir}`);
