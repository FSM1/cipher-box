import { MediaService, type MediaReader } from '@cipherbox/client';

/**
 * Dev serves the source entry as a transformed ES module under the
 * `Service-Worker-Allowed` root scope; the build emits a classic script.
 */
export function serviceWorkerScript(env: Partial<ImportMetaEnv>): {
  url: string;
  type: 'classic' | 'module';
} {
  return env.DEV ? { url: '/src/sw.ts', type: 'module' } : { url: '/sw.js', type: 'classic' };
}

/** This tab's streaming pipe, or `null` where the browser offers no Service Worker. */
export function createMediaService(reader: MediaReader): MediaService | null {
  if (!('serviceWorker' in navigator)) return null;
  const script = serviceWorkerScript(import.meta.env);
  return new MediaService({
    container: navigator.serviceWorker,
    scriptUrl: script.url,
    scriptType: script.type,
    reader,
  });
}
