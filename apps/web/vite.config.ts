import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import faro from '@grafana/faro-rollup-plugin';
import path from 'path';

export default defineConfig(({ mode }) => {
  const faroUrl = process.env.VITE_FARO_URL;
  const faroApiKey = process.env.GRAFANA_FARO_API_KEY;

  return {
    plugins: [
      react(),
      // Upload source maps to Grafana Faro in production/staging builds
      ...(faroUrl && faroApiKey && mode === 'production'
        ? [
            faro({
              appName: 'cipherbox-web',
              appId: 'cipherbox-web',
              endpoint: faroUrl,
              apiKey: faroApiKey,
              stackId: process.env.GRAFANA_STACK_ID ?? '',
              // Upload source maps but don't emit them in the output
              keepSourcemaps: false,
              gzipContents: true,
            }),
          ]
        : []),
    ],
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
    build: {
      sourcemap: 'hidden', // Generate .map files but don't reference them in output JS
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
  };
});
