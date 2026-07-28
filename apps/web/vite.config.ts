import { fileURLToPath } from 'node:url';
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react()],
  // The engine worker dynamically imports the wasm-bindgen ES module, which a
  // classic worker cannot do (blueprint/web-client.md "WASM packaging").
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
    port: 5173,
    // The Web3Auth login popup posts its result back to the opener.
    headers: { 'Cross-Origin-Opener-Policy': 'same-origin-allow-popups' },
    proxy: { '/api': { target: 'http://localhost:3000', changeOrigin: true } },
  },
});
