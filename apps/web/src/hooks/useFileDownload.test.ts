import { createElement, type ReactNode } from 'react';
import type { EngineClient, MediaService } from '@cipherbox/client';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { REVOKE_AFTER_MS } from '../lib/saveBlob';
import { EngineProvider } from '../providers/EngineProvider';
import { trackSaves } from '../test/saveSpy';
import { useFileDownload, type SaveOutcome, type SaveRequest } from './useFileDownload';

/** The pipe this tab gets; `null` is the browser without a Service Worker. */
const mediaControl = { create: (): MediaService | null => null };
vi.mock('../engine/createMediaService', () => ({
  createMediaService: () => mediaControl.create(),
}));

const NODE = new Uint8Array(16).fill(3);

const file = (name: string): SaveRequest => ({ node: NODE, name, size: 12n });

const batch = (names: readonly string[]): SaveRequest[] => names.map(file);

/**
 * A pipe whose tickets only go idle when the test says so, which is what a
 * transfer still in flight looks like to the hook.
 */
type FakePipe = ReturnType<typeof fakePipe>;

function fakePipe() {
  const live = new Set<string>();
  const minted: string[] = [];
  const waiting = new Map<string, (outcome: { read: boolean; failure: string | null }) => void>();

  const service = {
    streaming: true,
    start: () => Promise.resolve(),
    dispose: () => Promise.resolve(),
    createStreamUrl: () => {
      const url = `/stream/ticket-${minted.length + 1}`;
      minted.push(url);
      live.add(url);
      return url;
    },
    whenStreamIdle: (url: string) =>
      new Promise((resolve: (outcome: { read: boolean; failure: string | null }) => void) => {
        waiting.set(url, resolve);
      }),
    revokeStreamUrl: (url: string) => live.delete(url),
  } as unknown as MediaService;

  return {
    service,
    live,
    minted,
    /** The transfer for this ticket ended, or the browser never began it. */
    finish: async (url: string, read = true): Promise<void> => {
      await act(async () => {
        waiting.get(url)?.({ read, failure: null });
        await Promise.resolve();
      });
    },
    /**
     * The broker gave up on this ticket's body. It still went idle having been
     * read, which is exactly what makes the failure the only signal.
     */
    abandon: async (url: string, failure: string): Promise<void> => {
      await act(async () => {
        waiting.get(url)?.({ read: true, failure });
        await Promise.resolve();
      });
    },
  };
}

function fakeEngine(
  download: () => Promise<ArrayBuffer> = () => Promise.resolve(new ArrayBuffer(0))
) {
  return {
    facade: {
      subscribe: () => () => undefined,
      snapshot: () => new Promise<never>(() => undefined),
      setFocus: () => Promise.resolve(),
      download: vi.fn(download),
    },
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
}

function mount(client: EngineClient) {
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(EngineProvider, { createClient: () => client, children });
  return renderHook(() => useFileDownload(), { wrapper });
}

/** Lets the chain a settled ticket started run to its end, under fake timers. */
async function settled(): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(0);
  });
}

async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

/** Ends a transfer and waits out the grace the save commits in. */
async function finished(pipe: FakePipe, url: string): Promise<void> {
  await pipe.finish(url);
  await settled();
  await advance(REVOKE_AFTER_MS);
}

let saves = trackSaves();

beforeEach(() => {
  saves.restore();
  saves = trackSaves();
});

afterEach(() => {
  saves.restore();
  mediaControl.create = () => null;
});

describe('bounding the tickets a streamed save leaves live', () => {
  it('holds the ticket for the whole transfer and for the grace that follows it', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      let saved: SaveOutcome | null = null;
      await act(async () => {
        void result.current.save(file('notes.txt')).then((outcome) => {
          saved = outcome;
        });
        await Promise.resolve();
      });

      // Revoking before the browser has read the bytes cancels the save.
      expect(saves.navigated).toEqual(['/stream/ticket-1']);
      expect([...pipe.live]).toEqual(['/stream/ticket-1']);
      expect(saved).toBeNull();

      await pipe.finish('/stream/ticket-1');
      await settled();

      expect(saved).toBe('saved');
      // The browser commits the save after the read settles, so the ticket has
      // to outlive the settle.
      await advance(REVOKE_AFTER_MS - 1);
      expect([...pipe.live]).toEqual(['/stream/ticket-1']);

      await advance(1);
      expect([...pipe.live]).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  /**
   * The defect a batch showed: the save that follows tore the one before it down
   * before the browser had committed it, which delivers an empty or misnamed
   * file with nothing to report.
   */
  it('holds the next save of a batch back until the one before it commits', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      await act(async () => {
        void result.current.saveAll(batch(['a.bin', 'b.bin']));
        await Promise.resolve();
      });

      await pipe.finish('/stream/ticket-1');
      await settled();

      expect(pipe.minted).toEqual(['/stream/ticket-1']);
      expect(saves.frames[0].isConnected).toBe(true);

      await advance(REVOKE_AFTER_MS);
      expect(saves.frames[0].isConnected).toBe(false);
      expect(pipe.minted).toEqual(['/stream/ticket-1', '/stream/ticket-2']);
      expect([...pipe.live]).toEqual(['/stream/ticket-2']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('reports a save the browser never fetched, and says so', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    let saved: SaveOutcome | null = null;
    await act(async () => {
      void result.current.save(file('notes.txt')).then((outcome) => {
        saved = outcome;
      });
      await Promise.resolve();
    });
    await pipe.finish('/stream/ticket-1', false);

    await waitFor(() => expect(saved).toBe('refused'));
    expect(result.current.error).toBe('the browser did not start the download');
  });

  it('reports a stream the broker gave up on as a failure, not a completed save', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    let saved: SaveOutcome | null = null;
    await act(async () => {
      void result.current.save(file('notes.txt')).then((outcome) => {
        saved = outcome;
      });
      await Promise.resolve();
    });
    await pipe.abandon('/stream/ticket-1', 'the record is gone');

    await waitFor(() => expect(saved).toBe('failed'));
    expect(result.current.error).toBe('the record is gone');
  });

  it('leaves one live ticket however many files a caller saves in a loop', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    const names = ['a.bin', 'b.bin', 'c.bin', 'd.bin', 'e.bin'];
    vi.useFakeTimers();
    try {
      let done = false;
      await act(async () => {
        void result.current.saveAll(batch(names)).then(() => {
          done = true;
        });
        await Promise.resolve();
      });

      for (let nth = 1; nth <= names.length; nth += 1) {
        expect(pipe.minted).toHaveLength(nth);
        expect(pipe.live.size).toBe(1);
        await pipe.finish(`/stream/ticket-${nth}`);
        await settled();
        await advance(REVOKE_AFTER_MS);
      }

      expect(done).toBe(true);
      expect(pipe.live.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('revokes a transfer still running when the tab drops the hook', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result, unmount } = mount(fakeEngine());

    await act(async () => {
      void result.current.save(file('notes.txt'));
      await Promise.resolve();
    });
    expect(pipe.live.size).toBe(1);

    unmount();
    expect(pipe.live.size).toBe(0);
  });

  it('leaves no grace running for a save the tab drops the hook during', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result, unmount } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      await act(async () => {
        void result.current.save(file('notes.txt'));
        await Promise.resolve();
      });
      await pipe.finish('/stream/ticket-1');
      await settled();
      expect(pipe.live.size).toBe(1);

      unmount();
      expect(pipe.live.size).toBe(0);
      expect(saves.frames[0].isConnected).toBe(false);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('abandons the rest of a batch when the tab drops the hook mid-grace', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result, unmount } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      await act(async () => {
        void result.current.saveAll(batch(['a.bin', 'b.bin']));
        await Promise.resolve();
      });
      await pipe.finish('/stream/ticket-1');
      await settled();
      expect(pipe.minted).toEqual(['/stream/ticket-1']);

      unmount();
      await settled();
      await advance(REVOKE_AFTER_MS);

      expect(pipe.minted).toEqual(['/stream/ticket-1']);
      expect(pipe.live.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('saving a selection', () => {
  it('carries a failed file forward and names it, rather than dropping the rest', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      let done = false;
      await act(async () => {
        void result.current.saveAll(batch(['a.bin', 'b.bin', 'c.bin'])).then(() => {
          done = true;
        });
        await Promise.resolve();
      });

      await finished(pipe, '/stream/ticket-1');
      await pipe.abandon('/stream/ticket-2', 'the record is gone');
      await settled();
      await advance(REVOKE_AFTER_MS);
      expect(pipe.minted).toHaveLength(3);
      await finished(pipe, '/stream/ticket-3');

      expect(done).toBe(true);
      expect(saves.navigated).toEqual(['/stream/ticket-1', '/stream/ticket-2', '/stream/ticket-3']);
      expect(result.current.error).toBe('could not download b.bin');
    } finally {
      vi.useRealTimers();
    }
  });

  it('stops at the file the browser refused, since it will refuse the rest too', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      let done = false;
      await act(async () => {
        void result.current.saveAll(batch(['a.bin', 'b.bin', 'c.bin'])).then(() => {
          done = true;
        });
        await Promise.resolve();
      });

      await finished(pipe, '/stream/ticket-1');
      await pipe.finish('/stream/ticket-2', false);
      await settled();

      expect(done).toBe(true);
      expect(pipe.minted).toHaveLength(2);
      expect(result.current.error).toBe('the browser did not start the download');
    } finally {
      vi.useRealTimers();
    }
  });
});

describe('the buffered fallback', () => {
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it('reports a read the facade refused as this file failing, not as a refusal', async () => {
    const engine = fakeEngine(() => Promise.reject(new Error('the record is gone')));
    const { result } = mount(engine);

    let saved: SaveOutcome | null = null;
    await act(async () => {
      saved = await result.current.save(file('notes.txt'));
    });

    expect(saved).toBe('failed');
    expect(saves.navigated).toEqual([]);
    expect(saves.clicked).toEqual([]);
    expect(result.current.error).toBe('the record is gone');

    act(() => result.current.clearError());
    expect(result.current.error).toBeNull();
  });

  it('revokes each blob url on its own timer, not at the end of the batch', async () => {
    const { revoked } = stubObjectUrls();
    const { result } = mount(fakeEngine(() => Promise.resolve(new ArrayBuffer(4))));

    vi.useFakeTimers();
    try {
      await act(async () => {
        await result.current.save({ node: NODE, name: 'a.bin', size: null });
        await result.current.save({ node: NODE, name: 'b.bin', size: null });
      });
      expect(saves.clicked.map((link) => link.href)).toEqual(['blob:fake/1', 'blob:fake/2']);
      expect(revoked).toEqual([]);

      // Revoking inside the click's own task cancels the save in some browsers.
      await act(async () => {
        await vi.advanceTimersByTimeAsync(999);
      });
      expect(revoked).toEqual([]);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(1);
      });
      expect(revoked).toEqual(['blob:fake/1', 'blob:fake/2']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('leaves no revoke running once the tab drops the hook', async () => {
    const { revoked } = stubObjectUrls();
    const { result, unmount } = mount(fakeEngine(() => Promise.resolve(new ArrayBuffer(4))));

    vi.useFakeTimers();
    try {
      await act(async () => {
        await result.current.save({ node: NODE, name: 'a.bin', size: null });
      });
      expect(revoked).toEqual([]);

      unmount();
      expect(revoked).toEqual(['blob:fake/1']);
      expect(vi.getTimerCount()).toBe(0);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(revoked).toEqual(['blob:fake/1']);
    } finally {
      vi.useRealTimers();
    }
  });

  /** A save whose bytes land after the unmount has no cleanup left to run. */
  it('leaves no revoke running for a save that landed after the unmount', async () => {
    const { revoked } = stubObjectUrls();
    let landed: (bytes: ArrayBuffer) => void = () => undefined;
    const { result, unmount } = mount(
      fakeEngine(() => new Promise<ArrayBuffer>((resolve) => (landed = resolve)))
    );

    vi.useFakeTimers();
    try {
      let saved: SaveOutcome | null = null;
      await act(async () => {
        void result.current.save({ node: NODE, name: 'a.bin', size: null }).then((outcome) => {
          saved = outcome;
        });
        await Promise.resolve();
      });

      unmount();
      await act(async () => {
        landed(new ArrayBuffer(4));
        await Promise.resolve();
      });

      expect(saved).toBe('saved');
      expect(revoked).toEqual(['blob:fake/1']);
      expect(vi.getTimerCount()).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  /** Object URLs the running test minted, so nothing else can be read for them. */
  function stubObjectUrls() {
    let minted = 0;
    const revoked: string[] = [];
    URL.createObjectURL = vi.fn(() => `blob:fake/${++minted}`);
    URL.revokeObjectURL = vi.fn((url: string) => revoked.push(url));
    return { revoked };
  }
});

describe('how a ticket save reaches the Service Worker', () => {
  it('keeps the frame alive past the read, then drops it', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    vi.useFakeTimers();
    try {
      let saved: SaveOutcome | null = null;
      await act(async () => {
        void result.current.save(file('notes.txt')).then((outcome) => {
          saved = outcome;
        });
        await Promise.resolve();
      });

      // Chromium issues an `<a download>` request without dispatching it to the
      // worker, so a clicked link would fetch the app shell off the origin.
      expect(saves.navigated).toEqual(['/stream/ticket-1']);
      expect(saves.clicked).toEqual([]);
      expect(saves.frames[0].isConnected).toBe(true);
      expect(saved).toBeNull();

      await pipe.finish('/stream/ticket-1');
      await settled();

      expect(saved).toBe('saved');
      expect(saves.frames[0].isConnected).toBe(true);

      await advance(REVOKE_AFTER_MS);
      expect(saves.frames[0].isConnected).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });
});
