import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { build, loadEnv, type Plugin } from 'vite';
import { defineConfig } from 'vitest/config';

import { missingDeployEnv } from './src/engine/config';

const OUT_DIR = fileURLToPath(new URL('dist', import.meta.url));
const SW_ENTRY = fileURLToPath(new URL('src/sw.ts', import.meta.url));
const SW_FILE = 'sw.js';
const MANIFEST_FILE = 'precache-manifest.json';

/**
 * The app-shell pair, sharing one build id: the manifest the Service Worker
 * precaches on install — every emitted chunk, as same-origin absolute paths —
 * and the worker itself, stamped with a digest of those same bytes so the shell
 * cache rotates with the output.
 *
 * The worker is a second pass so it lands unhashed at the output root — its
 * scope is bounded by its own URL path — and as a classic script, not the ES
 * module the app's chunk graph would emit.
 */
function appShell(): Plugin[] {
  let buildId: string | null = null;

  return [
    {
      name: 'cipherbox:precache-manifest',
      enforce: 'post',
      generateBundle(_options, bundle) {
        const fileNames = Object.keys(bundle)
          .filter((fileName) => !fileName.endsWith('.map'))
          .sort();

        const digest = createHash('sha256');
        for (const fileName of fileNames) {
          const output = bundle[fileName];
          digest.update(fileName);
          digest.update(output.type === 'chunk' ? output.code : output.source);
        }
        buildId = digest.digest('hex').slice(0, 16);

        const shell = fileNames.map((fileName) => `/${fileName}`);
        this.emitFile({
          type: 'asset',
          fileName: MANIFEST_FILE,
          source: `${JSON.stringify(shell, null, 2)}\n`,
        });
      },
    },
    {
      name: 'cipherbox:service-worker',
      apply: 'build',
      async closeBundle() {
        if (buildId === null)
          throw new Error('the precache manifest emitted no app-shell build id');
        await build({
          configFile: false,
          logLevel: 'warn',
          define: { __APP_SHELL_BUILD_ID__: JSON.stringify(buildId) },
          build: {
            outDir: OUT_DIR,
            emptyOutDir: false,
            rollupOptions: {
              input: SW_ENTRY,
              // `iife` keeps the classic-script contract: an `es` chunk reaching for
              // a dynamic import emits `import.meta`, which a classic worker rejects.
              output: { entryFileNames: SW_FILE, codeSplitting: false, format: 'iife' },
            },
          },
        });
        // The worker's bytes must vary per deploy or the browser finds no update
        // to install, and the shell it precached is never rotated.
        const emitted = await readFile(join(OUT_DIR, SW_FILE), 'utf8');
        if (!emitted.includes(buildId)) throw new Error(`${SW_FILE} did not take the build stamp`);
      },
    },
  ];
}

/**
 * Fails a deployment build whose login-critical environment is unset, so the
 * gap surfaces here instead of as a throw in the browser at first login.
 */
function deployEnvGate(): Plugin {
  return {
    name: 'cipherbox:deploy-env-gate',
    apply: 'build',
    config(_config, { mode }) {
      const env = loadEnv(mode, import.meta.dirname, 'VITE_');
      const missing = missingDeployEnv(env);
      if (missing.length > 0) {
        throw new Error(
          `a ${env.VITE_ENVIRONMENT} build cannot log in without ${missing.join(', ')}`
        );
      }
    },
  };
}

export default defineConfig({
  plugins: [react(), deployEnvGate(), ...appShell()],
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
