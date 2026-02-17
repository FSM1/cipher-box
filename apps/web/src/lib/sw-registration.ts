/**
 * Service Worker lifecycle management for the decrypt proxy.
 *
 * The SW intercepts /decrypt-stream/* URLs from media elements,
 * decrypts AES-CTR content, and returns proper HTTP responses.
 */

/**
 * Register the decrypt Service Worker.
 * Returns the registration or null if SW is not supported.
 */
export async function registerDecryptSW(): Promise<ServiceWorkerRegistration | null> {
  if (!('serviceWorker' in navigator)) {
    console.warn('[SW] Service Workers not supported in this browser');
    return null;
  }

  try {
    // In dev mode, Vite serves TS directly. In production, the SW
    // is compiled to /decrypt-sw.js via the Vite build config.
    const swUrl = import.meta.env.DEV ? '/src/workers/decrypt-sw.ts' : '/decrypt-sw.js';

    const registration = await navigator.serviceWorker.register(swUrl, {
      scope: '/',
    });

    // Wait for the SW to be ready to accept messages
    await navigator.serviceWorker.ready;
    return registration;
  } catch (err) {
    console.error('[SW] Registration failed:', err);
    return null;
  }
}

/**
 * Send a message to the active Service Worker controller.
 */
export function sendToSW(message: unknown): void {
  navigator.serviceWorker.controller?.postMessage(message);
}

/**
 * Check whether a Service Worker controller is active.
 */
export function isSwActive(): boolean {
  return 'serviceWorker' in navigator && !!navigator.serviceWorker.controller;
}

/**
 * Wait for the SW controller to become available.
 * Resolves immediately if already active, otherwise waits for
 * the controllerchange event. Times out after 5 seconds.
 */
export function waitForSW(): Promise<void> {
  if (navigator.serviceWorker.controller) {
    return Promise.resolve();
  }

  return new Promise<void>((resolve) => {
    const timeout = setTimeout(() => {
      // Fallback: resolve anyway so the app doesn't hang
      resolve();
    }, 5000);

    navigator.serviceWorker.addEventListener(
      'controllerchange',
      () => {
        clearTimeout(timeout);
        resolve();
      },
      { once: true }
    );
  });
}

/**
 * Update the auth token stored in the Service Worker.
 */
export function updateSwToken(token: string): void {
  sendToSW({ type: 'update-token', token });
}

/**
 * Set the API base URL in the Service Worker.
 */
export function setSwApiBase(url: string): void {
  sendToSW({ type: 'set-api-base', url });
}

/**
 * Register a decrypt stream context in the Service Worker.
 * After calling this, set the media element's src to
 * `/decrypt-stream/{fileMetaIpnsName}` for transparent decryption.
 */
export function registerStream(params: {
  fileMetaIpnsName: string;
  fileKey: string;
  iv: string;
  cid: string;
  totalSize: number;
  mimeType: string;
}): void {
  sendToSW({ type: 'register-stream', ...params });
}

/**
 * Remove a decrypt stream context and its cached data from the SW.
 */
export function unregisterStream(fileMetaIpnsName: string): void {
  sendToSW({ type: 'unregister-stream', fileMetaIpnsName });
}
