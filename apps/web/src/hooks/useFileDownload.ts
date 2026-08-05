/**
 * Saving one file to disk: the facade's verified read, handed to the browser as
 * an opaque blob. The bytes are plaintext, so the object URL is revoked as soon
 * as the download has started.
 */

import { useCallback, useState } from 'react';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Never a renderable type: a blob URL is same-origin with the app. */
const OPAQUE = 'application/octet-stream';

/**
 * The save commits a task or two after the click; Firefox and Safari cancel it
 * silently if the URL is gone by then. Short, because the bytes are plaintext.
 */
const REVOKE_AFTER_MS = 1_000;

export interface FileDownload {
  error: string | null;
  save(node: Uint8Array, name: string): Promise<void>;
  /** Drops a failure the user has moved on from. */
  clearError(): void;
}

export function useFileDownload(): FileDownload {
  const client = useEngine();
  const [error, setError] = useState<string | null>(null);

  const save = useCallback(
    async (node: Uint8Array, name: string): Promise<void> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return;
      }
      setError(null);
      try {
        const bytes = await client.facade.download(node);
        saveToDisk(new Blob([bytes], { type: OPAQUE }), name);
      } catch (failure: unknown) {
        setError(errorMessage(failure));
      }
    },
    [client]
  );

  return { error, save, clearError: useCallback(() => setError(null), []) };
}

function saveToDisk(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
}
