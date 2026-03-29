// Dev-mode Service Worker wrapper.
// Loads the real decrypt-sw.ts (Vite-transformed) via importScripts.
// Served from public/ so the browser allows scope: '/' without the
// Service-Worker-Allowed header that Vite can't reliably set.
/* global importScripts */
importScripts('/src/workers/decrypt-sw.ts');
