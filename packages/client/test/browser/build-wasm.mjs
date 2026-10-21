// Builds the conformance-featured WASM module and its wasm-bindgen glue for the
// browser suite. Runs before Playwright (see the `test:browser` script). The
// `conformance` feature pulls in the engine test kit and the seam conformance
// bridge (crates/wasm/src/conformance.rs); the production WASM artifact is built
// without it and never includes these bindings. The `observer` feature adds the
// session-free record read that the Node suite (`test:node`) drives.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const here = import.meta.dirname;
const repoRoot = resolve(here, '../../../..');
const outDir = resolve(here, 'pkg');
const wasmArtifact = resolve(repoRoot, 'target/wasm32-unknown-unknown/debug/cipherbox_wasm.wasm');

const run = (command, args) => execFileSync(command, args, { cwd: repoRoot, stdio: 'inherit' });

// A debug engine overflows the 1 MiB default wasm stack on its deeper sync
// paths. 8 MiB is the stack the desktop engine thread gets for the same debug
// paths. The flag goes after `--`, because `RUSTFLAGS` would replace the
// getrandom backend that `.cargo/config.toml` sets for this target.
const STACK_BYTES = 8 * 1024 * 1024;

run('cargo', [
  'rustc',
  '-p',
  'cipherbox-wasm',
  '--lib',
  '--features',
  'conformance,observer',
  '--target',
  'wasm32-unknown-unknown',
  '--',
  '-C',
  `link-arg=-zstack-size=${STACK_BYTES}`,
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
