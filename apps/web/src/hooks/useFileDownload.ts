/**
 * Saving one file to disk. The browser pulls it through the Service Worker byte
 * pipe when this tab can stream (blueprint/web-client.md "Streaming media"), so
 * no plaintext is held in the tab; without a controlling worker it falls back to
 * the facade's buffered read handed over as an opaque blob.
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { errorMessage } from '../lib/errorMessage';
import { OPAQUE, REVOKE_AFTER_MS, saveBlobToDisk } from '../lib/saveBlob';
import { streamTicket } from '../lib/streamTicket';
import { useEngine, useMediaService } from '../providers/EngineProvider';
import { displayName } from '../vault/displayName';

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
  const deferred = useRef(new Map<ReturnType<typeof setTimeout>, () => void>());
  /** The release the last streamed save deferred, so a batch can wait it out. */
  const settling = useRef<Promise<void>>(Promise.resolve());
  const mounted = useRef(true);

  /** Runs every deferred release now, for a hook that has nothing left to wait for. */
  const releaseDeferred = useCallback(() => {
    for (const [timer, release] of deferred.current) {
      clearTimeout(timer);
      release();
    }
    deferred.current.clear();
  }, []);

  /**
   * Holds a release back for `REVOKE_AFTER_MS`, and resolves once it has run.
   * The browser commits a save a task or two after the navigation or the click
   * that raised it, and a source withdrawn inside that window cancels the save
   * with no error to report.
   */
  const deferRelease = useCallback(
    (release: () => void): Promise<void> =>
      new Promise<void>((released) => {
        const run = (): void => {
          release();
          released();
        };
        const timer = setTimeout(() => {
          deferred.current.delete(timer);
          run();
        }, REVOKE_AFTER_MS);
        deferred.current.set(timer, run);
      }),
    []
  );

  // Unmount cuts a transfer that is still running, and its ticket has no timer
  // of its own to fall back on. A deferred release left behind outlives the hook
  // that owns it: it holds plaintext alive, and it fires against whatever the
  // document and `URL.revokeObjectURL` are a second later.
  useEffect(() => {
    const held = tickets.current;
    mounted.current = true;
    return () => {
      mounted.current = false;
      releaseDeferred();
      for (const url of held) media?.revokeStreamUrl(url);
      held.clear();
    };
  }, [media, releaseDeferred]);

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
            // The read settling is the tab having pushed the last window, not
            // the browser having committed the save. A batch starts its next
            // save in the same task, so an immediate teardown here is what
            // leaves one file of a batch empty or under a name of the
            // browser's choosing.
            settling.current = deferRelease(() => {
              frame.remove();
              tickets.current.delete(ticket);
              media.revokeStreamUrl(ticket);
            });
            if (!mounted.current) releaseDeferred();
          }
        }
      }

      try {
        const bytes = await client.facade.download(node);
        const url = URL.createObjectURL(new Blob([bytes], { type: OPAQUE }));
        saveBlobToDisk(url, name);
        void deferRelease(() => URL.revokeObjectURL(url));
        // The cleanup this timer is owned by has already run.
        if (!mounted.current) releaseDeferred();
        return 'saved';
      } catch (failure: unknown) {
        setError(errorMessage(failure));
        return 'failed';
      }
    },
    [client, media, deferRelease, releaseDeferred]
  );

  const saveAll = useCallback(
    async (files: readonly SaveRequest[]): Promise<void> => {
      const failed: string[] = [];
      for (const file of files) {
        const outcome = await save(file);
        // A browser that blocks the second download blocks every one after it.
        if (outcome === 'refused') break;
        if (outcome === 'failed') failed.push(displayName(file.name));
        // One live ticket and one frame at a time, however long the selection:
        // the next navigation waits out the grace this save commits in.
        await settling.current;
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

/**
 * A navigation rather than a link, because Chromium issues an `<a download>`
 * request without dispatching it to the Service Worker — the link form walks
 * past the pipe and fetches the app shell. The pipe's `content-disposition`
 * turns the navigation into a save, and its `sandbox` keeps a body that commits
 * as a document out of this frame's reach.
 */
function ticketFrame(url: string): HTMLIFrameElement {
  const frame = document.createElement('iframe');
  frame.hidden = true;
  frame.src = url;
  document.body.append(frame);
  return frame;
}
