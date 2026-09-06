import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';
import { desktopPlatformOf } from './scripts/buildEnv.mjs';

/** Fixed so `devUrl` in `tauri.conf.json` names one port, and not web's 5173. */
const DEV_PORT = 5174;

// Applied here as well as in `scripts/tauri.mjs`, so a bare `vite build` and
// the test run resolve the same value the packaged build does.
process.env.VITE_DESKTOP_PLATFORM = desktopPlatformOf(process.env);

export default defineConfig({
  resolve: {
    alias: {
      // Resolve the shim to the file rather than the subpath, which pnpm's
      // nested layout otherwise doubles up.
      'process/browser': fileURLToPath(new URL('node_modules/process/browser.js', import.meta.url)),
    },
  },
  define: { global: 'globalThis' },
  // The Tauri CLI owns the terminal; a cleared screen eats its output.
  clearScreen: false,
  server: { port: DEV_PORT, strictPort: true },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
    setupFiles: ['./src/test-setup.ts'],
  },
});
