import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { build, type Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

const OUT_DIR = fileURLToPath(new URL('dist', import.meta.url));
const SW_ENTRY = fileURLToPath(new URL('src/sw.ts', import.meta.url));
const SW_FILE = 'sw.js';
const MANIFEST_FILE = 'precache-manifest.json';

/**
 * The app-shell manifest the Service Worker precaches on install: every emitted
 * chunk, as same-origin absolute paths. Never the worker itself — a worker that
 * precached itself could never be replaced.
 */
function precacheManifest(): Plugin {
  return {
    name: 'cipherbox:precache-manifest',
    enforce: 'post',
    generateBundle(_options, bundle) {
      const shell = Object.keys(bundle)
        .filter((fileName) => !fileName.endsWith('.map'))
        .map((fileName) => `/${fileName}`)
        .sort();
      this.emitFile({
        type: 'asset',
        fileName: MANIFEST_FILE,
        source: `${JSON.stringify(shell, null, 2)}\n`,
      });
    },
  };
}

/**
 * A separate pass so the worker lands unhashed at the output root — its scope is
 * bounded by its own URL path — and as a classic script, not the ES module the
 * app's chunk graph would emit.
 */
function serviceWorkerBuild(): Plugin {
  return {
    name: 'cipherbox:service-worker',
    apply: 'build',
    async closeBundle() {
      await build({
        configFile: false,
        logLevel: 'warn',
        build: {
          outDir: OUT_DIR,
          emptyOutDir: false,
          rollupOptions: {
            input: SW_ENTRY,
            output: { entryFileNames: SW_FILE, codeSplitting: false },
          },
        },
      });
    },
  };
}

export default defineConfig({
  plugins: [react(), precacheManifest(), serviceWorkerBuild()],
  // `@cipherbox/client`'s engine worker dynamically imports the wasm-bindgen ES
  // module, which a classic worker cannot do (blueprint/web-client.md).
  worker: { format: 'es' },
  resolve: {
    alias: {
      // Resolve the shim to the file rather than the subpath, which pnpm's
      // nested layout otherwise doubles up.
      'process/browser': fileURLToPath(new URL('node_modules/process/browser.js', import.meta.url)),
    },
  },
  define: { global: 'globalThis' },
  server: {
    headers: {
      // The Web3Auth login popup posts its result back to the opener.
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
      // Lets the dev worker at /src/sw.ts claim the root scope it needs.
      'Service-Worker-Allowed': '/',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
