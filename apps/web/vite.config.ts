import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import faro from '@grafana/faro-rollup-plugin';
import path from 'path';

export default defineConfig(({ mode }) => {
  const faroUrl = process.env.VITE_FARO_URL;
  const faroApiKey = process.env.GRAFANA_FARO_API_KEY;
  const faroStackId = process.env.GRAFANA_STACK_ID;
  const faroEnabled = !!(faroUrl && faroApiKey && faroStackId && mode === 'production');

  return {
    plugins: [
      react(),
      // Upload source maps to Grafana Faro in production/staging builds
      ...(faroEnabled
        ? [
            faro({
              appName: 'cipherbox-web',
              appId: 'cipherbox-web',
              endpoint: faroUrl!,
              apiKey: faroApiKey!,
              stackId: faroStackId!,
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
      // Only generate hidden source maps when Faro upload is active
      ...(faroEnabled ? { sourcemap: 'hidden' as const } : {}),
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
