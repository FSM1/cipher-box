import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import path from 'path';
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // Point to the actual file to avoid path doubling
      'process/browser': path.resolve(__dirname, 'node_modules/process/browser.js'),
      buffer: 'buffer',
    },
  },
  define: {
    global: 'globalThis',
  },
  server: {
    port: 5173,
    headers: {
      'Cross-Origin-Opener-Policy': 'same-origin-allow-popups',
    },
    proxy: {
      '/api': {
        target: 'http://localhost:3000',
        changeOrigin: true,
      },
    },
  },
});
