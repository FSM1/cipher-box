// Emits the engine's wasm-bindgen ES module + binary for the bundler to
// fingerprint (blueprint/web-client.md "WASM packaging"). Release profile,
// no `conformance` feature.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

const here = import.meta.dirname;
const repoRoot = resolve(here, '../../..');
const outDir = resolve(here, '../src/wasm');

const run = (command, args) => execFileSync(command, args, { cwd: repoRoot, stdio: 'inherit' });

// Ask cargo where it writes rather than assuming `target/`, so a redirected
// target dir cannot leave wasm-bindgen consuming a stale binary.
const { target_directory: targetDir } = JSON.parse(
  execFileSync('cargo', ['metadata', '--no-deps', '--format-version', '1'], {
    cwd: repoRoot,
    encoding: 'utf8',
  })
);

// `--locked`: these are the bytes that ship, so lock drift must fail the build
// rather than silently re-resolve the crypto crates' dependency graph.
run('cargo', [
  'build',
  '--locked',
  '-p',
  'cipherbox-wasm',
  '--release',
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
  resolve(targetDir, 'wasm32-unknown-unknown/release/cipherbox_wasm.wasm'),
]);

console.log(`Engine WASM + bindings written to ${outDir}`);
