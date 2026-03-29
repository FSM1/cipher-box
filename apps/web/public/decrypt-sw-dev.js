// Dev-mode Service Worker wrapper (ES module).
// Served from public/ so the browser allows scope: '/' without the
// Service-Worker-Allowed header that Vite can't reliably set.
// Uses module import so Vite-transformed /src files load correctly.
import '/src/workers/decrypt-sw.ts';
