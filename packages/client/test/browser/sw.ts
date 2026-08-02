/**
 * The Service Worker entry for the browser suite. It is the production entry
 * verbatim — the suite exercises the real worker, not a stand-in — and lives at
 * the dev-server root so a `/sw.ts` registration takes root scope.
 */
import '../../src/sw/serviceWorker.js';
