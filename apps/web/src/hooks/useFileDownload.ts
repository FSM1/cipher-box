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
 * nothing about the next. `saved` means the broker did not give up on the read,
 * which is as much as this tab can know once the bytes are the browser's.
 */
export type SaveOutcome = 'saved' | 'refused' | 'failed';

/** One file to save. */
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
  save(file: SaveRequest): Promise<SaveOutcome>;
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
    async ({ node, name, size }: SaveRequest): Promise<SaveOutcome> => {
      if (client === null) {
        setError('the engine is not ready yet');
        return 'refused';
      }
      setError(null);

      if (media !== null) {
        const ticket = streamTicket(media, node, size, OPAQUE, name);
        if (ticket !== null) {
          tickets.current.add(ticket);
          const frame = ticketFrame(ticket);
          try {
            const idle = await media.whenStreamIdle(ticket, STREAM_START_MS);
            if (idle.failure !== null) {
              setError(idle.failure);
              return 'failed';
            }
            if (!idle.read) {
              setError(NEVER_FETCHED);
              return 'refused';
            }
            return 'saved';
          } finally {
            // The browser owns the transfer once the read settles, so dropping
            // the frame cannot cut it.
            frame.remove();
            tickets.current.delete(ticket);
            media.revokeStreamUrl(ticket);
          }
        }
      }

      try {
        const bytes = await client.facade.download(node);
        const url = URL.createObjectURL(new Blob([bytes], { type: OPAQUE }));
        saveBlobToDisk(url, name);
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
        const outcome = await save(file);
        // A browser that blocks the second download blocks every one after it.
        if (outcome === 'refused') break;
        if (outcome === 'failed') failed.push(file.name);
      }
      if (failed.length === 0) return;
      // Each save clears the banner the one before it set, so the batch reports
      // here or nowhere; whatever stopped it keeps the last word.
      const summary = `could not download ${failed.join(', ')}`;
      setError((stopped) => (stopped === null ? summary : `${summary}; ${stopped}`));
    },
    [save]
  );

  return { error, save, saveAll, clearError: useCallback(() => setError(null), []) };
}

/** A blob URL never involves the worker, so the link form is safe for it. */
function saveBlobToDisk(url: string, name: string): void {
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  link.rel = 'noopener';
  document.body.append(link);
  link.click();
  link.remove();
}

/**
 * Drives a ticket save, as a navigation rather than a link: Chromium issues an
 * `<a download>` request without dispatching it to the Service Worker, so the
 * link form walks past the pipe to the origin, which answers a ticket path with
 * the app shell. The pipe's `content-disposition` makes the navigation a save,
 * and its `sandbox` is what keeps the plaintext out of this frame's reach if a
 * body ever commits as a document here.
 */
function ticketFrame(url: string): HTMLIFrameElement {
  const frame = document.createElement('iframe');
  frame.hidden = true;
  frame.src = url;
  document.body.append(frame);
  return frame;
}
