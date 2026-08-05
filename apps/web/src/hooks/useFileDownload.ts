/**
 * Saving one file to disk. The browser pulls it through the Service Worker byte
 * pipe when this tab can stream (blueprint/web-client.md "Streaming media"), so
 * no plaintext is held in the tab; without a controlling worker it falls back to
 * the facade's buffered read handed over as an opaque blob.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { errorMessage } from '../lib/errorMessage';
import { streamTicket } from '../lib/streamTicket';
import { useEngine, useMediaService } from '../providers/EngineProvider';

/** Never a renderable type: a blob URL is same-origin with the app. */
const OPAQUE = 'application/octet-stream';

/**
 * The save commits a task or two after the click; Firefox and Safari cancel it
 * silently if the URL is gone by then. Short, because the bytes are plaintext.
 */
const REVOKE_AFTER_MS = 1_000;

export interface FileDownload {
  error: string | null;
  /** @param size the engine's byte count; `null` forces the buffered read. */
  save(node: Uint8Array, name: string, size: bigint | null): Promise<void>;
  /** Drops a failure the user has moved on from. */
  clearError(): void;
}

export function useFileDownload(): FileDownload {
  const client = useEngine();
  const media = useMediaService();
  const [error, setError] = useState<string | null>(null);
  const tickets = useRef<string[]>([]);

  // A streamed save reads for as long as the transfer lasts, so its ticket
  // cannot be dropped on a timer the way a fully materialized blob URL can.
  useEffect(() => {
    const held = tickets.current;
    return () => {
      for (const url of held.splice(0)) media?.revokeStreamUrl(url);
    };
  }, [media]);

  const save = useCallback(
    async (node: Uint8Array, name: string, size: bigint | null): Promise<void> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return;
      }
      setError(null);

      const ticket = streamTicket(media, node, size, OPAQUE);
      if (ticket !== null) {
        tickets.current.push(ticket);
        saveToDisk(ticket, name);
        return;
      }

      try {
        const bytes = await client.facade.download(node);
        const url = URL.createObjectURL(new Blob([bytes], { type: OPAQUE }));
        saveToDisk(url, name);
        setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
      } catch (failure: unknown) {
        setError(errorMessage(failure));
      }
    },
    [client, media]
  );

  return { error, save, clearError: useCallback(() => setError(null), []) };
}

function saveToDisk(url: string, name: string): void {
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
}
