import { defineConfig } from 'vite';
import path from 'path';

export default defineConfig({
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  envPrefix: ['VITE_', 'TAURI_'],
  resolve: {
    alias: {
      'process/browser': path.resolve(__dirname, 'node_modules/process/browser.js'),
      buffer: 'buffer',
    },
  },
  define: {
    global: 'globalThis',
  },
  build: {
    target: 'esnext',
    minify: !process.env.TAURI_DEBUG ? 'esbuild' : false,
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
