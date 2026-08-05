/**
 * The upload path: `File` handles in, facade write handles out
 * (blueprint/web-client.md "Content paths"). A slice of plaintext is read and
 * transferred into the engine in one step and never copied through React state.
 *
 * Rows are transient UI state keyed on the upload's op id; what the vault holds
 * stays the snapshot store's word alone (UI state law).
 */

import { useCallback, useEffect, useRef, useState } from 'react';
import { EngineRequestError } from '@cipherbox/client';
import type { EventDescriptor } from '@cipherbox/client';
import { errorMessage } from '../lib/errorMessage';
import { useEngine } from '../providers/EngineProvider';

/** Peak heap is one slice, however large the file. */
const CHUNK_BYTES = 1024 * 1024;

/** How long a settled row stays on screen before it retires itself. */
const SETTLED_ROW_MILLIS = 1500;

/** Where an upload has got to; `staging` is the only rung the engine does not name. */
export type UploadPhase =
  | 'staging'
  | 'queued'
  | 'uploading'
  | 'uploaded'
  | 'stalled'
  | 'cancelled'
  | 'failed';

const ACTIVE_PHASES: readonly UploadPhase[] = ['staging', 'queued', 'uploading', 'stalled'];

/** Settled with nothing left to say, so the row clears itself. */
const RETIRING_PHASES: readonly UploadPhase[] = ['uploaded', 'cancelled'];

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
  /** Set once the write commits, so a cancel names the op without a render read. */
  opId: bigint | null;
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
  const timers = useRef(new Map<string, ReturnType<typeof setTimeout>>());
  // Uploads run one at a time: `beginWrite` reserves the whole version against
  // the staging budget, so files started together contend for room only one has.
  const queue = useRef<Promise<void>>(Promise.resolve());
  // Replies and events cross on different channels, so an op can be reported
  // before its `commitWrite` reply lands. Only events from inside a commit
  // window may claim a slot, so a foreign op's report cannot accumulate here.
  const committing = useRef(false);
  const unbound = useRef(new Map<string, Partial<UploadEntry>>());

  const patch = useCallback((id: string, change: Partial<UploadEntry>) => {
    setUploads((rows) => rows.map((row) => (row.id === id ? { ...row, ...change } : row)));
  }, []);

  const forget = useCallback((id: string) => {
    stopRetire(timers.current, id);
    jobs.current.delete(id);
    cancelled.current.delete(id);
    unbind(rowByOp.current, id);
    setUploads((rows) => rows.filter((row) => row.id !== id));
  }, []);

  const retire = useCallback(
    (id: string) => {
      stopRetire(timers.current, id);
      timers.current.set(
        id,
        setTimeout(() => forget(id), SETTLED_ROW_MILLIS)
      );
    },
    [forget]
  );

  useEffect(() => {
    const pending = timers.current;
    return () => {
      for (const timer of pending.values()) clearTimeout(timer);
      pending.clear();
    };
  }, []);

  /** Lands one engine update on a row, retiring it once nothing is left to do. */
  const apply = useCallback(
    (id: string, change: Partial<UploadEntry>) => {
      patch(id, change);
      if (change.phase === undefined) return;
      // A dead letter can follow the blocks landing, so a row that moves on must
      // not be swept by the timer its earlier phase scheduled.
      if (RETIRING_PHASES.includes(change.phase)) retire(id);
      else stopRetire(timers.current, id);
    },
    [patch, retire]
  );

  useEffect(() => {
    if (engine === null) return;
    return engine.facade.subscribe((event) => {
      const update = rowUpdate(event);
      if (update === null) return;
      const key = update.opId.toString();
      const row = rowByOp.current.get(key);
      if (row === undefined) {
        if (committing.current) unbound.current.set(key, update.change);
        return;
      }
      apply(row, update.change);
    });
  }, [apply, engine]);

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
        apply(id, { phase: 'cancelled', error: null });
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
        job.opId = opId;
        rowByOp.current.set(opId.toString(), id);
        patch(id, { opId, phase: 'queued' });

        const early = unbound.current.get(opId.toString());
        unbound.current.clear();
        if (early !== undefined) apply(id, early);
        // A cancel that arrived mid-commit has an op to name now.
        if (cancelled.current.has(id)) dropOp(id, opId);
      } catch (error) {
        await release();
        if (cancelled.current.has(id)) {
          apply(id, { phase: 'cancelled', error: null });
          return;
        }
        patch(id, {
          phase: 'failed',
          error: errorMessage(error),
          code: error instanceof EngineRequestError ? (error.code ?? null) : null,
        });
      }
    },
    [apply, dropOp, engine, patch, retire]
  );

  const enqueue = useCallback(
    (id: string) => {
      queue.current = queue.current.then(() => run(id));
    },
    [run]
  );

  const upload = useCallback(
    (files: readonly File[], parent: Uint8Array) => {
      if (files.length === 0) return;
      const started = files.map((file) => {
        const id = `upload-${(sequence += 1)}`;
        jobs.current.set(id, { file, parent, opId: null });
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
      setUploads((rows) => [...rows, ...started]);
      for (const row of started) enqueue(row.id);
    },
    [enqueue]
  );

  const cancel = useCallback(
    (id: string) => {
      cancelled.current.add(id);
      const opId = jobs.current.get(id)?.opId;
      if (opId != null) dropOp(id, opId);
    },
    [dropOp]
  );

  const retry = useCallback(
    (id: string) => {
      const job = jobs.current.get(id);
      if (job === undefined) return;
      cancelled.current.delete(id);
      unbind(rowByOp.current, id);
      job.opId = null;
      patch(id, { phase: 'staging', progress: 0, opId: null, error: null, code: null });
      enqueue(id);
    },
    [enqueue, patch]
  );

  return { uploads, upload, cancel, retry, dismiss: forget };
}

function stopRetire(timers: Map<string, ReturnType<typeof setTimeout>>, id: string): void {
  const timer = timers.get(id);
  if (timer === undefined) return;
  clearTimeout(timer);
  timers.delete(id);
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
