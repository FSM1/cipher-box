import { afterEach, describe, expect, it, vi } from 'vitest';
import { browserContactScanner } from './contactScanner';

const CODE_HEX = '00ff10';

interface Stubs {
  stop: ReturnType<typeof vi.fn>;
  getUserMedia: ReturnType<typeof vi.fn>;
  detect: ReturnType<typeof vi.fn>;
}

interface BrowserOptions {
  getUserMedia?: Stubs['getUserMedia'];
  formats?: string[];
  play?: () => Promise<void>;
}

let playing: () => Promise<void> = () => Promise.resolve();

/** A browser that carries both halves the scanner needs. */
function browser(detect: Stubs['detect'], options: BrowserOptions = {}): Stubs {
  const stop = vi.fn();
  const stream = { getTracks: () => [{ stop }] } as unknown as MediaStream;
  const media = options.getUserMedia ?? vi.fn(() => Promise.resolve(stream));
  playing = options.play ?? (() => Promise.resolve());
  Object.defineProperty(globalThis.navigator, 'mediaDevices', {
    value: { getUserMedia: media },
    configurable: true,
  });
  Object.defineProperty(globalThis, 'BarcodeDetector', {
    value: class {
      static getSupportedFormats = () => Promise.resolve(options.formats ?? ['qr_code']);
      detect = detect;
    },
    configurable: true,
  });
  return { stop, getUserMedia: media, detect };
}

function preview() {
  return { play: () => playing(), srcObject: null } as unknown as HTMLVideoElement;
}

/** A promise that never settles, as a hung camera or detector answers. */
function hangs<T>(): Promise<T> {
  return new Promise<T>(() => undefined);
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, 'BarcodeDetector');
  Object.defineProperty(globalThis.navigator, 'mediaDevices', {
    value: undefined,
    configurable: true,
  });
});

describe('the browser contact scanner', () => {
  it('reports no capability where the browser cannot decode a code', async () => {
    browser(vi.fn());
    Reflect.deleteProperty(globalThis, 'BarcodeDetector');

    await expect(browserContactScanner.supported()).resolves.toBe(false);
  });

  it('reports no capability where the browser offers no camera', async () => {
    browser(vi.fn());
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: undefined,
      configurable: true,
    });

    await expect(browserContactScanner.supported()).resolves.toBe(false);
  });

  it('reports no capability where the detector reads no QR code', async () => {
    browser(vi.fn(), { formats: ['ean_13', 'code_128'] });

    await expect(browserContactScanner.supported()).resolves.toBe(false);
  });

  it('asks for the camera only when a scan starts', async () => {
    const stubs = browser(vi.fn(() => Promise.resolve([{ rawValue: CODE_HEX }])));

    await expect(browserContactScanner.supported()).resolves.toBe(true);
    expect(stubs.getUserMedia).not.toHaveBeenCalled();

    await browserContactScanner.scan({ video: preview(), signal: new AbortController().signal });
    expect(stubs.getUserMedia).toHaveBeenCalledTimes(1);
  });

  it('answers the first frame that carries a code and then releases the camera', async () => {
    const stubs = browser(vi.fn(() => Promise.resolve([{ rawValue: CODE_HEX }])));

    const text = await browserContactScanner.scan({
      video: preview(),
      signal: new AbortController().signal,
    });

    expect(text).toBe(CODE_HEX);
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('releases the camera when the caller leaves the scan', async () => {
    const holder = new AbortController();
    const stubs = browser(
      vi.fn(() => {
        holder.abort();
        return Promise.resolve([]);
      })
    );

    const text = await browserContactScanner.scan({ video: preview(), signal: holder.signal });

    expect(text).toBeNull();
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('releases the camera when playback never settles and the caller leaves', async () => {
    const holder = new AbortController();
    const stubs = browser(vi.fn(), { play: hangs });

    const scan = browserContactScanner.scan({ video: preview(), signal: holder.signal });
    holder.abort();

    await expect(scan).resolves.toBeNull();
    expect(stubs.detect).not.toHaveBeenCalled();
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('releases the camera when a detect pass never settles and the caller leaves', async () => {
    const holder = new AbortController();
    const stubs = browser(
      vi.fn(() => {
        queueMicrotask(() => holder.abort());
        return hangs();
      })
    );

    const text = await browserContactScanner.scan({ video: preview(), signal: holder.signal });

    expect(text).toBeNull();
    expect(stubs.detect).toHaveBeenCalledTimes(1);
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('releases the camera when no detect pass settles before the budget runs out', async () => {
    vi.useFakeTimers();
    const stubs = browser(vi.fn(() => hangs()));
    try {
      const scan = browserContactScanner.scan({
        video: preview(),
        signal: new AbortController().signal,
      });
      await vi.advanceTimersByTimeAsync(20_000);

      await expect(scan).resolves.toBeNull();
      expect(stubs.stop).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('releases the camera inside the gap between frames, without waiting it out', async () => {
    vi.useFakeTimers();
    const holder = new AbortController();
    const stubs = browser(vi.fn(() => Promise.resolve([])));
    try {
      const scan = browserContactScanner.scan({ video: preview(), signal: holder.signal });
      await vi.advanceTimersByTimeAsync(0);
      holder.abort();
      await vi.advanceTimersByTimeAsync(0);

      await expect(scan).resolves.toBeNull();
      expect(stubs.detect).toHaveBeenCalledTimes(1);
      expect(stubs.stop).toHaveBeenCalledTimes(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('releases the camera when a detect pass throws', async () => {
    const stubs = browser(vi.fn(() => Promise.reject(new Error('detector failed'))));

    await expect(
      browserContactScanner.scan({ video: preview(), signal: new AbortController().signal })
    ).rejects.toThrow('detector failed');
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('passes on a camera the member refused, and holds no stream', async () => {
    const stubs = browser(vi.fn(), {
      getUserMedia: vi.fn(() => Promise.reject(new Error('NotAllowedError'))),
    });

    await expect(
      browserContactScanner.scan({ video: preview(), signal: new AbortController().signal })
    ).rejects.toThrow('NotAllowedError');
    expect(stubs.stop).not.toHaveBeenCalled();
  });
});
