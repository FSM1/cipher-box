/**
 * Build the decrypt Service Worker as a standalone script.
 * Called as a post-build step after `vite build`.
 *
 * Uses Vite's build API in lib mode to compile the SW TypeScript
 * to a single IIFE file at dist/decrypt-sw.js.
 */
import { build } from 'vite';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

await build({
  root,
  configFile: false,
  logLevel: 'warn',
  build: {
    lib: {
      entry: path.resolve(root, 'src/workers/decrypt-sw.ts'),
      formats: ['iife'],
      name: 'DecryptSW',
    },
    outDir: path.resolve(root, 'dist'),
    emptyOutDir: false,
    minify: true,
    rollupOptions: {
      output: {
        entryFileNames: 'decrypt-sw.js',
      },
    },
  },
});

console.log('  Service Worker built: dist/decrypt-sw.js');
