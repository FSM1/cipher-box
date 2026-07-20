// Builds the conformance-featured WASM module and its wasm-bindgen glue for the
// browser suite. Runs before Playwright (see the `test:browser` script). The
// `conformance` feature pulls in the engine test kit and the seam conformance
// bridge (crates/wasm/src/conformance.rs); the production WASM artifact is built
// without it and never includes these bindings.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const here = import.meta.dirname;
const repoRoot = resolve(here, '../../../..');
const outDir = resolve(here, 'pkg');
const wasmArtifact = resolve(repoRoot, 'target/wasm32-unknown-unknown/debug/cipherbox_wasm.wasm');

const run = (command, args) => execFileSync(command, args, { cwd: repoRoot, stdio: 'inherit' });

run('cargo', [
  'build',
  '-p',
  'cipherbox-wasm',
  '--features',
  'conformance',
  '--target',
  'wasm32-unknown-unknown',
]);

run('wasm-bindgen', [
  '--target',
  'web',
  '--out-dir',
  outDir,
  '--out-name',
  'cipherbox_wasm',
  wasmArtifact,
]);

console.log(`Conformance WASM + bindings written to ${outDir}`);
