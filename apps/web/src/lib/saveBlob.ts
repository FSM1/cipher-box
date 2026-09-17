/**
 * Handing plaintext bytes the tab already holds to the browser as a save. The
 * streamed route lives in `useFileDownload`; this is the buffered one, shared by
 * every caller that gets an `ArrayBuffer` back from the facade.
 */

/** Never a renderable type: a blob URL is same-origin with the app. */
export const OPAQUE = 'application/octet-stream';

/**
 * The save commits a task or two after the click; Firefox and Safari cancel it
 * silently if the URL is gone by then. Short, because the bytes are plaintext.
 */
export const REVOKE_AFTER_MS = 1_000;

/** A blob URL never involves the worker, so the link form is safe for it. */
export function saveBlobToDisk(url: string, name: string): void {
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
}
