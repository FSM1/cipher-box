import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [react()],
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
    // The Web3Auth login popup posts its result back to the opener.
    headers: { 'Cross-Origin-Opener-Policy': 'same-origin-allow-popups' },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
