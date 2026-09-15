import { afterEach, describe, expect, it, vi } from 'vitest';
import { browserContactScanner } from './contactScanner';

const CODE_HEX = '00ff10';

interface Stubs {
  stop: ReturnType<typeof vi.fn>;
  getUserMedia: ReturnType<typeof vi.fn>;
  detect: ReturnType<typeof vi.fn>;
}

/** A browser that carries both halves the scanner needs. */
function browser(detect: Stubs['detect'], getUserMedia?: Stubs['getUserMedia']): Stubs {
  const stop = vi.fn();
  const stream = { getTracks: () => [{ stop }] } as unknown as MediaStream;
  const media = getUserMedia ?? vi.fn(() => Promise.resolve(stream));
  Object.defineProperty(globalThis.navigator, 'mediaDevices', {
    value: { getUserMedia: media },
    configurable: true,
  });
  Object.defineProperty(globalThis, 'BarcodeDetector', {
    value: class {
      detect = detect;
    },
    configurable: true,
  });
  return { stop, getUserMedia: media, detect };
}

function preview() {
  return { play: vi.fn(() => Promise.resolve()), srcObject: null } as unknown as HTMLVideoElement;
}

afterEach(() => {
  Reflect.deleteProperty(globalThis, 'BarcodeDetector');
  Object.defineProperty(globalThis.navigator, 'mediaDevices', {
    value: undefined,
    configurable: true,
  });
});

describe('the browser contact scanner', () => {
  it('reports no capability where the browser cannot decode a code', () => {
    browser(vi.fn());
    Reflect.deleteProperty(globalThis, 'BarcodeDetector');

    expect(browserContactScanner.supported()).toBe(false);
  });

  it('reports no capability where the browser offers no camera', () => {
    browser(vi.fn());
    Object.defineProperty(globalThis.navigator, 'mediaDevices', {
      value: undefined,
      configurable: true,
    });

    expect(browserContactScanner.supported()).toBe(false);
  });

  it('asks for the camera only when a scan starts', async () => {
    const stubs = browser(vi.fn(() => Promise.resolve([{ rawValue: CODE_HEX }])));

    expect(browserContactScanner.supported()).toBe(true);
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

  it('releases the camera when a detect pass throws', async () => {
    const stubs = browser(vi.fn(() => Promise.reject(new Error('detector failed'))));

    await expect(
      browserContactScanner.scan({ video: preview(), signal: new AbortController().signal })
    ).rejects.toThrow('detector failed');
    expect(stubs.stop).toHaveBeenCalledTimes(1);
  });

  it('passes on a camera the member refused, and holds no stream', async () => {
    const stubs = browser(
      vi.fn(),
      vi.fn(() => Promise.reject(new Error('NotAllowedError')))
    );

    await expect(
      browserContactScanner.scan({ video: preview(), signal: new AbortController().signal })
    ).rejects.toThrow('NotAllowedError');
    expect(stubs.stop).not.toHaveBeenCalled();
  });
});
