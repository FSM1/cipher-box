/**
 * The production Service Worker entry (blueprint/web-client.md "Content paths").
 *
 * This is a worker entry — register it, never import it into the UI realm.
 */

import { installServiceWorker, type ServiceWorkerScopeLike } from './install.js';

installServiceWorker(globalThis as unknown as ServiceWorkerScopeLike);
