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

/** How long a minted ticket waits for the browser to open the save it triggered. */
const STREAM_START_MS = 30_000;

const NEVER_FETCHED = 'the browser did not start the download';

/**
 * How a save ended. `refused` is the save never being attempted, which will hold
 * for the next file too; `failed` is this one file's read giving out, which says
 * nothing about the next. A stream that dies after its first byte still goes
 * idle having been read, so only the broker's failure tells it from a whole file.
 */
export type SaveOutcome = 'saved' | 'refused' | 'failed';

/** One file of a batch save. */
export interface SaveRequest {
  readonly node: Uint8Array;
  /** The name the file lands under on disk. */
  readonly name: string;
  /** The engine's byte count; `null` forces the buffered read. */
  readonly size: bigint | null;
}

export interface FileDownload {
  error: string | null;
  /** Resolves once the file's bytes have stopped moving. */
  save(node: Uint8Array, name: string, size: bigint | null): Promise<SaveOutcome>;
  /** Saves each file in turn, stopping at a refusal and naming what failed. */
  saveAll(files: readonly SaveRequest[]): Promise<void>;
  /** Drops a failure the user has moved on from. */
  clearError(): void;
}

export function useFileDownload(): FileDownload {
  const client = useEngine();
  const media = useMediaService();
  const [error, setError] = useState<string | null>(null);
  const tickets = useRef(new Set<string>());

  // Unmount cuts a transfer that is still running, and its ticket has no timer
  // of its own to fall back on.
  useEffect(() => {
    const held = tickets.current;
    return () => {
      for (const url of held) media?.revokeStreamUrl(url);
      held.clear();
    };
  }, [media]);

  const save = useCallback(
    async (node: Uint8Array, name: string, size: bigint | null): Promise<SaveOutcome> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return 'refused';
      }
      setError(null);

      if (media !== null) {
        const ticket = streamTicket(media, node, size, OPAQUE);
        if (ticket !== null) {
          tickets.current.add(ticket);
          // Subscribed before the fetch it watches: a body that dies on its
          // first window fails before a later subscribe would be listening.
          let abandoned: string | null = null;
          const unsubscribe = media.onStreamError((failure) => {
            if (failure.url === ticket) abandoned ??= failure.message;
          });
          saveToDisk(ticket, name);
          try {
            const read = await media.whenStreamIdle(ticket, STREAM_START_MS);
            if (abandoned !== null) {
              setError(abandoned);
              return 'failed';
            }
            if (!read) {
              setError(NEVER_FETCHED);
              return 'refused';
            }
            return 'saved';
          } finally {
            unsubscribe();
            tickets.current.delete(ticket);
            media.revokeStreamUrl(ticket);
          }
        }
      }

      try {
        const bytes = await client.facade.download(node);
        const url = URL.createObjectURL(new Blob([bytes], { type: OPAQUE }));
        saveToDisk(url, name);
        setTimeout(() => URL.revokeObjectURL(url), REVOKE_AFTER_MS);
        return 'saved';
      } catch (failure: unknown) {
        setError(errorMessage(failure));
        return 'failed';
      }
    },
    [client, media]
  );

  const saveAll = useCallback(
    async (files: readonly SaveRequest[]): Promise<void> => {
      const failed: string[] = [];
      for (const file of files) {
        const outcome = await save(file.node, file.name, file.size);
        // A browser that blocks the second download blocks every one after it.
        if (outcome === 'refused') break;
        if (outcome === 'failed') failed.push(file.name);
      }
      // A per-file failure is reported here or nowhere: each save clears the
      // banner the one before it set.
      if (failed.length > 0) setError(`could not download ${failed.join(', ')}`);
    },
    [save]
  );

  return { error, save, saveAll, clearError: useCallback(() => setError(null), []) };
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
