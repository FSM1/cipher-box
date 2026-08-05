import type { ReactNode } from 'react';
import { EngineRequestError } from '@cipherbox/client';
import type { EngineClient, EventDescriptor, WriteTarget } from '@cipherbox/client';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { useDropUpload } from './useDropUpload';

const PARENT = new Uint8Array(16).fill(4);
const CHUNK_BYTES = 1024 * 1024;

/** The write-handle surface the hook drives, with every call recorded in order. */
function uploadEngine() {
  const listeners = new Set<(event: EventDescriptor) => void>();
  const log: string[] = [];
  let handles = 0n;
  let ops = 0n;

  const facade = {
    subscribe(listener: (event: EventDescriptor) => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: () => new Promise<never>(() => undefined),
    setFocus: () => Promise.resolve(),
    beginWrite: vi.fn((target: WriteTarget, size: number) => {
      log.push(`begin:${'name' in target ? target.name : 'version'}:${size}`);
      handles += 1n;
      return Promise.resolve(handles);
    }),
    pushChunk: vi.fn((_handle: bigint, chunk: ArrayBuffer) => {
      log.push(`push:${chunk.byteLength}`);
      return Promise.resolve();
    }),
    commitWrite: vi.fn(() => {
      log.push('commit');
      ops += 1n;
      return Promise.resolve(ops);
    }),
    abortWrite: vi.fn(() => {
      log.push('abort');
      return Promise.resolve();
    }),
    cancelUpload: vi.fn((opId: bigint) => {
      log.push(`cancelUpload:${opId}`);
      return Promise.resolve();
    }),
  };

  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return {
    client,
    facade,
    log,
    emit: (event: EventDescriptor) => {
      for (const listener of listeners) listener(event);
    },
  };
}

function mount(client: EngineClient) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <EngineProvider createClient={() => client}>{children}</EngineProvider>
  );
  return renderHook(() => useDropUpload(), { wrapper });
}

function file(name: string, bytes: number): File {
  return new File([new Uint8Array(bytes)], name);
}

const progress = (opId: bigint, confirmed: number, total: number): EventDescriptor => ({
  kind: 'opProgress',
  opId,
  node: new Uint8Array(16),
  phase: 'uploadProgress',
  blocksConfirmed: confirmed,
  blocksTotal: total,
  error: null,
});

afterEach(() => {
  vi.useRealTimers();
});

describe('driving an upload through the facade write handles', () => {
  it('slices the file at the chunk boundary and commits one op', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('report.pdf', CHUNK_BYTES + 100)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('queued'));
    expect(engine.log).toEqual([
      `begin:report.pdf:${CHUNK_BYTES + 100}`,
      `push:${CHUNK_BYTES}`,
      'push:100',
      'commit',
    ]);
    expect(engine.facade.beginWrite.mock.calls[0][0]).toEqual({
      parent: PARENT,
      name: 'report.pdf',
    });
    expect(result.current.uploads[0].opId).toBe(1n);
  });

  it('commits an empty file without pushing a chunk', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('empty.txt', 0)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('queued'));
    expect(engine.log).toEqual(['begin:empty.txt:0', 'commit']);
  });

  it('runs queued files one at a time', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10), file('b.bin', 20)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[1].phase).toBe('queued'));
    expect(engine.log).toEqual([
      'begin:a.bin:10',
      'push:10',
      'commit',
      'begin:b.bin:20',
      'push:20',
      'commit',
    ]);
  });
});

describe('reporting what the engine says about the op', () => {
  it('tracks confirmed blocks as the drain reports them', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => engine.emit(progress(1n, 3, 4)));

    expect(result.current.uploads[0].phase).toBe('uploading');
    expect(result.current.uploads[0].progress).toBeCloseTo(0.75);
  });

  it('binds an event that landed before commitWrite answered', async () => {
    const engine = uploadEngine();
    engine.facade.commitWrite.mockImplementationOnce(() => {
      // The drain can report the op before the commit reply crosses back.
      engine.emit(progress(1n, 2, 2));
      return Promise.resolve(1n);
    });
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('uploading'));
    expect(result.current.uploads[0].progress).toBe(1);
  });

  it('ignores op progress for an op this tab never opened', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => engine.emit(progress(99n, 1, 2)));

    expect(result.current.uploads[0].phase).toBe('queued');
  });

  it('holds a failed attempt open, because the drain retries it', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadFailed',
        blocksConfirmed: null,
        blocksTotal: null,
        error: 'no reachable pin provider',
      })
    );

    expect(result.current.uploads[0].phase).toBe('stalled');
    expect(result.current.uploads[0].error).toBe('no reachable pin provider');
  });

  it('settles a dead-lettered op as terminal', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => engine.emit({ kind: 'deadLetter', opId: 1n, reason: 'targetGone' }));

    expect(result.current.uploads[0].phase).toBe('failed');
    expect(result.current.uploads[0].error).toContain('targetGone');
  });

  it('retires a published row on its own', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadCompleted',
        blocksConfirmed: 2,
        blocksTotal: 2,
        error: null,
      })
    );
    expect(result.current.uploads[0].phase).toBe('uploaded');

    await act(async () => {
      vi.advanceTimersByTime(2000);
    });
    expect(result.current.uploads).toHaveLength(0);
  });

  it('keeps a row a dead letter overtook, rather than sweeping it on the old timer', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadCompleted',
        blocksConfirmed: 2,
        blocksTotal: 2,
        error: null,
      })
    );
    // The record still has to publish, so a dead letter can follow the blocks.
    act(() => engine.emit({ kind: 'deadLetter', opId: 1n, reason: 'targetGone' }));

    await act(async () => {
      vi.advanceTimersByTime(2000);
    });
    expect(result.current.uploads).toHaveLength(1);
    expect(result.current.uploads[0].phase).toBe('failed');
  });
});

describe('cancelling', () => {
  it('aborts a staging write instead of committing it', async () => {
    const engine = uploadEngine();
    let admit = () => undefined as void;
    engine.facade.beginWrite.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          admit = () => resolve(1n);
        })
    );
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    act(() => result.current.cancel(result.current.uploads[0].id));
    await act(async () => {
      admit();
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('cancelled'));
    expect(engine.facade.commitWrite).not.toHaveBeenCalled();
    expect(engine.facade.abortWrite).toHaveBeenCalledWith(1n);
  });

  it('asks the engine to drop an op that has already committed', async () => {
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => result.current.cancel(result.current.uploads[0].id));
    expect(engine.facade.cancelUpload).toHaveBeenCalledWith(1n);

    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadCancelled',
        blocksConfirmed: null,
        blocksTotal: null,
        error: null,
      })
    );
    expect(result.current.uploads[0].phase).toBe('cancelled');
  });

  it('retires a row the engine cancelled, rather than stranding it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => result.current.cancel(result.current.uploads[0].id));
    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadCancelled',
        blocksConfirmed: null,
        blocksTotal: null,
        error: null,
      })
    );

    await act(async () => {
      vi.advanceTimersByTime(2000);
    });
    expect(result.current.uploads).toHaveLength(0);
  });

  it('keeps a retried row that the cancel retirement timer would have swept', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    const engine = uploadEngine();
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    act(() => result.current.cancel(result.current.uploads[0].id));
    act(() =>
      engine.emit({
        kind: 'opProgress',
        opId: 1n,
        node: new Uint8Array(16),
        phase: 'uploadCancelled',
        blocksConfirmed: null,
        blocksTotal: null,
        error: null,
      })
    );
    expect(result.current.uploads[0].phase).toBe('cancelled');

    // The retry button is on screen for the whole retirement window.
    await act(async () => {
      result.current.retry(result.current.uploads[0].id);
    });
    await act(async () => {
      vi.advanceTimersByTime(2000);
    });

    expect(result.current.uploads).toHaveLength(1);
    expect(result.current.uploads[0].phase).toBe('queued');
    expect(result.current.uploads[0].opId).toBe(2n);
    expect(engine.facade.commitWrite).toHaveBeenCalledTimes(2);
  });

  it('shows a refused cancel without moving the row off the upload', async () => {
    const engine = uploadEngine();
    engine.facade.cancelUpload.mockRejectedValueOnce(
      new EngineRequestError('the version is already publishing', 'tooLateToCancel')
    );
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].opId).toBe(1n));

    await act(async () => {
      result.current.cancel(result.current.uploads[0].id);
    });

    expect(result.current.uploads[0].phase).toBe('queued');
    expect(result.current.uploads[0].error).toBe('the version is already publishing');
  });
});

describe('refused writes', () => {
  it('keeps the engine code so the caller can classify an over-budget refusal', async () => {
    const engine = uploadEngine();
    engine.facade.beginWrite.mockRejectedValueOnce(
      new EngineRequestError('this write needs 900 bytes but only 100 are free', 'overBudget')
    );
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('big.bin', 900)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('failed'));
    expect(result.current.uploads[0].code).toBe('overBudget');
    expect(result.current.uploads[0].error).toContain('only 100 are free');
    expect(engine.facade.commitWrite).not.toHaveBeenCalled();
  });

  it('releases the handle when a chunk is refused', async () => {
    const engine = uploadEngine();
    engine.facade.pushChunk.mockRejectedValueOnce(
      new EngineRequestError('pushed 3 of 5 bytes', 'contentSizeMismatch')
    );
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('failed'));
    expect(engine.facade.abortWrite).toHaveBeenCalledWith(1n);
  });

  it('re-runs a failed row from the file it was dropped with', async () => {
    const engine = uploadEngine();
    engine.facade.beginWrite.mockRejectedValueOnce(new Error('nope'));
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].phase).toBe('failed'));

    await act(async () => {
      result.current.retry(result.current.uploads[0].id);
    });

    await waitFor(() => expect(result.current.uploads[0].phase).toBe('queued'));
    expect(result.current.uploads[0].error).toBeNull();
    expect(result.current.uploads[0].code).toBeNull();
  });

  it('drops a dismissed row', async () => {
    const engine = uploadEngine();
    engine.facade.beginWrite.mockRejectedValueOnce(new Error('nope'));
    const { result } = mount(engine.client);

    await act(async () => {
      result.current.upload([file('a.bin', 10)], PARENT);
    });
    await waitFor(() => expect(result.current.uploads[0].phase).toBe('failed'));

    act(() => result.current.dismiss(result.current.uploads[0].id));

    expect(result.current.uploads).toHaveLength(0);
  });
});
