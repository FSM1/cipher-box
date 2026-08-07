import { createElement, type ReactNode } from 'react';
import type { EngineClient, MediaService } from '@cipherbox/client';
import { act, renderHook, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { useFileDownload } from './useFileDownload';

/** The pipe this tab gets; `null` is the browser without a Service Worker. */
const mediaControl = { create: (): MediaService | null => null };
vi.mock('../engine/createMediaService', () => ({
  createMediaService: () => mediaControl.create(),
}));

const NODE = new Uint8Array(16).fill(3);

/**
 * A pipe whose tickets only go idle when the test says so, which is what a
 * transfer still in flight looks like to the hook.
 */
function fakePipe() {
  const live = new Set<string>();
  const minted: string[] = [];
  const waiting = new Map<string, (read: boolean) => void>();

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
      new Promise<boolean>((resolve) => {
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
        waiting.get(url)?.(read);
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

const clicked: string[] = [];
const originalClick = HTMLAnchorElement.prototype.click;

beforeEach(() => {
  clicked.length = 0;
  HTMLAnchorElement.prototype.click = function click(this: HTMLAnchorElement) {
    clicked.push(this.getAttribute('href') ?? '');
  };
});

afterEach(() => {
  HTMLAnchorElement.prototype.click = originalClick;
  mediaControl.create = () => null;
});

describe('bounding the tickets a streamed save leaves live', () => {
  it('holds the ticket for the whole transfer and drops it the moment it ends', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    let saved: boolean | null = null;
    await act(async () => {
      void result.current.save(NODE, 'notes.txt', 12n).then((ok) => {
        saved = ok;
      });
      await Promise.resolve();
    });

    // Revoking before the browser has read the bytes cancels the save.
    expect(clicked).toEqual(['/stream/ticket-1']);
    expect([...pipe.live]).toEqual(['/stream/ticket-1']);
    expect(saved).toBeNull();

    await pipe.finish('/stream/ticket-1');

    await waitFor(() => expect(saved).toBe(true));
    expect([...pipe.live]).toEqual([]);
  });

  it('reports a save the browser never fetched, and says so', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    let saved: boolean | null = null;
    await act(async () => {
      void result.current.save(NODE, 'notes.txt', 12n).then((ok) => {
        saved = ok;
      });
      await Promise.resolve();
    });
    await pipe.finish('/stream/ticket-1', false);

    await waitFor(() => expect(saved).toBe(false));
    expect(pipe.live.size).toBe(0);
    expect(result.current.error).toBe('the browser did not start the download');
  });

  it('leaves one live ticket however many files a caller saves in a loop', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result } = mount(fakeEngine());

    const names = ['a.bin', 'b.bin', 'c.bin', 'd.bin', 'e.bin'];
    let done = false;
    await act(async () => {
      void (async () => {
        for (const name of names) await result.current.save(NODE, name, 12n);
        done = true;
      })();
      await Promise.resolve();
    });

    for (let file = 1; file <= names.length; file += 1) {
      expect(pipe.live.size).toBe(1);
      expect(pipe.minted).toHaveLength(file);
      await pipe.finish(`/stream/ticket-${file}`);
    }

    await waitFor(() => expect(done).toBe(true));
    expect(pipe.live.size).toBe(0);
  });

  it('revokes a transfer still running when the tab drops the hook', async () => {
    const pipe = fakePipe();
    mediaControl.create = () => pipe.service;
    const { result, unmount } = mount(fakeEngine());

    await act(async () => {
      void result.current.save(NODE, 'notes.txt', 12n);
      await Promise.resolve();
    });
    expect(pipe.live.size).toBe(1);

    unmount();
    expect(pipe.live.size).toBe(0);
  });
});

describe('the buffered fallback', () => {
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  it('reads through the facade and reports a refusal instead of saving', async () => {
    const engine = fakeEngine(() => Promise.reject(new Error('the record is gone')));
    const { result } = mount(engine);

    await act(async () => {
      await result.current.save(NODE, 'notes.txt', 12n);
    });

    expect(clicked).toEqual([]);
    expect(result.current.error).toBe('the record is gone');

    act(() => result.current.clearError());
    expect(result.current.error).toBeNull();
  });

  it('revokes each blob url on its own timer rather than at unmount', async () => {
    let minted = 0;
    const revoked: string[] = [];
    URL.createObjectURL = vi.fn(() => `blob:fake/${++minted}`);
    URL.revokeObjectURL = vi.fn((url: string) => revoked.push(url));
    const { result } = mount(fakeEngine(() => Promise.resolve(new ArrayBuffer(4))));

    vi.useFakeTimers();
    try {
      await act(async () => {
        await result.current.save(NODE, 'a.bin', null);
        await result.current.save(NODE, 'b.bin', null);
      });
      expect(clicked).toEqual(['blob:fake/1', 'blob:fake/2']);
      expect(revoked).toEqual([]);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(revoked).toEqual(['blob:fake/1', 'blob:fake/2']);
    } finally {
      vi.useRealTimers();
    }
  });
});
