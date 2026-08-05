/**
 * The upload path: `File` handles in, facade write handles out
 * (blueprint/web-client.md "Content paths"). One slice of plaintext exists at a
 * time and is transferred into the engine, never copied through React state.
 *
 * Rows are transient UI state keyed on the upload's op id; what the vault holds
 * stays the snapshot store's word alone (UI state law).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { EngineRequestError } from '@cipherbox/client';
import type { EventDescriptor } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Plaintext crosses to the engine one slice at a time; peak heap is one slice. */
const CHUNK_BYTES = 1024 * 1024;

/** How long a settled row stays on screen before it retires itself. */
const SETTLED_ROW_MILLIS = 1500;

/**
 * Where an upload has got to. `uploaded` means the version's blocks are on the
 * network, not that its record published; `stalled` is one attempt the drain
 * will retry, where `failed` is terminal.
 */
export type UploadPhase =
  | 'staging'
  | 'queued'
  | 'uploading'
  | 'uploaded'
  | 'stalled'
  | 'cancelled'
  | 'failed';

const ACTIVE_PHASES: readonly UploadPhase[] = ['staging', 'queued', 'uploading', 'stalled'];

/** Whether the engine still has work for this row. */
export function isActiveUpload(phase: UploadPhase): boolean {
  return ACTIVE_PHASES.includes(phase);
}

export interface UploadEntry {
  /** Row identity from the drop; the op id only exists once the write commits. */
  id: string;
  name: string;
  size: number;
  phase: UploadPhase;
  /** Blocks confirmed as a fraction, once the drain reports them. */
  progress: number;
  opId: bigint | null;
  /** The engine's diagnostic for the current phase, or `null`. */
  error: string | null;
  /** The engine's stable code for a refused write, so a caller classifies it. */
  code: string | null;
}

export interface DropUpload {
  uploads: readonly UploadEntry[];
  /** Stages and commits each file into `parent`, one at a time. */
  upload(files: readonly File[], parent: Uint8Array): void;
  /** Aborts a staging write, or asks the engine to drop a committed op. */
  cancel(id: string): void;
  /** Re-runs a settled row from the `File` it was dropped with. */
  retry(id: string): void;
  /** Clears a settled row. */
  dismiss(id: string): void;
}

interface Job {
  file: File;
  parent: Uint8Array;
}

/** What one engine event says about the row holding its op. */
interface RowUpdate {
  opId: bigint;
  change: Partial<UploadEntry>;
}

let sequence = 0;

export function useDropUpload(): DropUpload {
  const engine = useEngine();
  const [uploads, setUploads] = useState<readonly UploadEntry[]>([]);
  const jobs = useRef(new Map<string, Job>());
  const cancelled = useRef(new Set<string>());
  const rowByOp = useRef(new Map<string, string>());
  const timers = useRef(new Set<ReturnType<typeof setTimeout>>());
  // Uploads run one at a time: `beginWrite` reserves the whole version against
  // the staging budget, so files started together contend for room only one has.
  const queue = useRef<Promise<void>>(Promise.resolve());
  // A drain that reports an op before its `commitWrite` reply lands has no row
  // to update yet; one slot covers it, because only one commit is ever open and
  // the op id it is claimed under is unique.
  const committing = useRef(false);
  const unbound = useRef<RowUpdate | null>(null);

  const patch = useCallback((id: string, change: Partial<UploadEntry>) => {
    setUploads((rows) => rows.map((row) => (row.id === id ? { ...row, ...change } : row)));
  }, []);

  const forget = useCallback((id: string) => {
    jobs.current.delete(id);
    cancelled.current.delete(id);
    unbind(rowByOp.current, id);
    setUploads((rows) => rows.filter((row) => row.id !== id));
  }, []);

  const retire = useCallback(
    (id: string) => {
      const timer = setTimeout(() => {
        timers.current.delete(timer);
        forget(id);
      }, SETTLED_ROW_MILLIS);
      timers.current.add(timer);
    },
    [forget]
  );

  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const timer of pending) clearTimeout(timer);
      pending.clear();
    };
  }, []);

  useEffect(() => {
    if (engine === null) return;
    return engine.facade.subscribe((event) => {
      const update = rowUpdate(event);
      if (update === null) return;
      const row = rowByOp.current.get(update.opId.toString());
      if (row === undefined) {
        if (committing.current) unbound.current = update;
        return;
      }
      patch(row, update.change);
      if (update.change.phase === 'uploaded') retire(row);
    });
  }, [engine, patch, retire]);

  /** Asks the engine to drop a committed op; a refusal says why on the row. */
  const dropOp = useCallback(
    (id: string, opId: bigint): void => {
      const facade = engine?.facade;
      if (facade === undefined) return;
      facade.cancelUpload(opId).catch((error: unknown) => {
        patch(id, { error: errorMessage(error) });
      });
    },
    [engine, patch]
  );

  const run = useCallback(
    async (id: string) => {
      const job = jobs.current.get(id);
      if (job === undefined) return;
      const facade = engine?.facade;
      if (facade === undefined) {
        patch(id, { phase: 'failed', error: 'the engine is not running yet' });
        return;
      }

      let handle: bigint | null = null;
      const release = async (): Promise<void> => {
        if (handle !== null) await facade.abortWrite(handle).catch(() => undefined);
        handle = null;
      };
      /** True once the row is cancelled, having released what it held. */
      const abandoned = async (): Promise<boolean> => {
        if (!cancelled.current.has(id)) return false;
        await release();
        patch(id, { phase: 'cancelled', error: null });
        retire(id);
        return true;
      };

      try {
        if (await abandoned()) return;
        handle = await facade.beginWrite(
          { parent: job.parent, name: job.file.name },
          job.file.size
        );
        for (let offset = 0; offset < job.file.size; offset += CHUNK_BYTES) {
          if (await abandoned()) return;
          // Read and handed over in one step: the push detaches the buffer, so
          // no plaintext slice outlives the call that consumed it.
          await facade.pushChunk(
            handle,
            await job.file.slice(offset, offset + CHUNK_BYTES).arrayBuffer()
          );
        }
        if (await abandoned()) return;

        committing.current = true;
        let opId: bigint;
        try {
          opId = await facade.commitWrite(handle);
        } finally {
          committing.current = false;
        }
        handle = null;

        rowByOp.current.set(opId.toString(), id);
        const early = unbound.current?.opId === opId ? unbound.current.change : undefined;
        unbound.current = null;
        patch(id, { opId, phase: 'queued', ...early });
        if (early?.phase === 'uploaded') retire(id);
        // A cancel that arrived mid-commit has an op to name now.
        if (cancelled.current.has(id)) dropOp(id, opId);
      } catch (error) {
        await release();
        if (cancelled.current.has(id)) {
          patch(id, { phase: 'cancelled', error: null });
          retire(id);
          return;
        }
        patch(id, {
          phase: 'failed',
          error: errorMessage(error),
          code: error instanceof EngineRequestError ? (error.code ?? null) : null,
        });
      }
    },
    [dropOp, engine, patch, retire]
  );

  const enqueue = useCallback(
    (id: string) => {
      queue.current = queue.current.then(() => run(id));
    },
    [run]
  );

  const upload = useCallback(
    (files: readonly File[], parent: Uint8Array) => {
      const started = files.map((file) => {
        const id = `upload-${(sequence += 1)}`;
        jobs.current.set(id, { file, parent });
        return {
          id,
          name: file.name,
          size: file.size,
          phase: 'staging',
          progress: 0,
          opId: null,
          error: null,
          code: null,
        } satisfies UploadEntry;
      });
      if (started.length === 0) return;
      setUploads((rows) => [...rows, ...started]);
      for (const row of started) enqueue(row.id);
    },
    [enqueue]
  );

  const cancel = useCallback(
    (id: string) => {
      cancelled.current.add(id);
      const opId = uploads.find((row) => row.id === id)?.opId;
      // Still staging: the run loop reads the flag at its next chunk boundary.
      if (opId != null) dropOp(id, opId);
    },
    [dropOp, uploads]
  );

  const retry = useCallback(
    (id: string) => {
      if (!jobs.current.has(id)) return;
      cancelled.current.delete(id);
      unbind(rowByOp.current, id);
      patch(id, { phase: 'staging', progress: 0, opId: null, error: null, code: null });
      enqueue(id);
    },
    [enqueue, patch]
  );

  return { uploads, upload, cancel, retry, dismiss: forget };
}

function unbind(rowByOp: Map<string, string>, id: string): void {
  for (const [op, row] of rowByOp) {
    if (row === id) rowByOp.delete(op);
  }
}

function rowUpdate(event: EventDescriptor): RowUpdate | null {
  if (event.kind === 'deadLetter') {
    const error = `${event.reason}, so this upload will never publish`;
    return { opId: event.opId, change: { phase: 'failed', error } };
  }
  if (event.kind !== 'opProgress' || event.opId === null) return null;
  switch (event.phase) {
    case 'uploadStarted':
    case 'uploadProgress':
      return { opId: event.opId, change: { phase: 'uploading', progress: fraction(event) } };
    case 'uploadCompleted':
      return { opId: event.opId, change: { phase: 'uploaded', progress: 1, error: null } };
    case 'uploadFailed':
      return { opId: event.opId, change: { phase: 'stalled', error: event.error } };
    case 'uploadCancelled':
      return { opId: event.opId, change: { phase: 'cancelled', error: null } };
    default:
      return null;
  }
}

function fraction(event: { blocksConfirmed: number | null; blocksTotal: number | null }): number {
  const total = event.blocksTotal ?? 0;
  return total > 0 ? Math.min((event.blocksConfirmed ?? 0) / total, 1) : 0;
}
