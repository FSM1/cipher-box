/**
 * The camera leg of a contact exchange: a code offered as a QR, read into the
 * same text the paste field takes. This decodes a transport encoding and
 * nothing else — the binding verify stays the engine's
 * (blueprint/engine.md "Contact import").
 */

const CODE_FORMAT = 'qr_code';

/** How long one scan holds the camera before it reports that it read nothing. */
const SCAN_BUDGET_MS = 20_000;

/** Between two detect passes; a member holds a code still for far longer. */
const FRAME_INTERVAL_MS = 200;

interface DetectedCode {
  rawValue: string;
}

interface Detector {
  detect(source: CanvasImageSource): Promise<DetectedCode[]>;
}

interface DetectorConstructor {
  new (init: { formats: string[] }): Detector;
  getSupportedFormats(): Promise<string[]>;
}

interface ScanTarget {
  /** The preview the member aims; also the frame source the detector reads. */
  video: HTMLVideoElement;
  /** Aborted when the member leaves the scan, which stops the camera. */
  signal: AbortSignal;
}

export interface ContactScanner {
  /** Whether this browser can read a QR code from the camera at all. */
  supported(): Promise<boolean>;
  /**
   * The text of the first frame that carries a code, or `null` when the budget
   * passed or the member left. It rejects when the camera itself is refused.
   */
  scan(target: ScanTarget): Promise<string | null>;
}

function detectorConstructor(): DetectorConstructor | null {
  const candidate = (globalThis as { BarcodeDetector?: DetectorConstructor }).BarcodeDetector;
  return typeof candidate?.getSupportedFormats === 'function' ? candidate : null;
}

function camera(): MediaDevices | null {
  const devices = globalThis.navigator?.mediaDevices;
  return typeof devices?.getUserMedia === 'function' ? devices : null;
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The work's value, or `null` once the member leaves or the budget passes.
 * Nothing the scan loop waits on — playback, a detect pass, the frame gap —
 * ends on the signal by itself, so one of them would hold the camera open.
 */
function firstOf<T>(work: Promise<T>, signal: AbortSignal, deadline: number): Promise<T | null> {
  if (signal.aborted) return Promise.resolve(null);
  return new Promise<T | null>((resolve, reject) => {
    function done() {
      clearTimeout(timer);
      signal.removeEventListener('abort', giveUp);
    }
    function giveUp() {
      done();
      resolve(null);
    }
    const timer = setTimeout(giveUp, Math.max(0, deadline - Date.now()));
    signal.addEventListener('abort', giveUp, { once: true });
    work.then(
      (value) => {
        done();
        resolve(value);
      },
      (failure: unknown) => {
        done();
        reject(failure instanceof Error ? failure : new Error(String(failure)));
      }
    );
  });
}

/** The browser seam. Tests pass their own `ContactScanner` instead. */
export const browserContactScanner: ContactScanner = {
  async supported() {
    const Constructor = detectorConstructor();
    if (Constructor === null || camera() === null) return false;
    try {
      return (await Constructor.getSupportedFormats()).includes(CODE_FORMAT);
    } catch {
      return false;
    }
  },

  async scan({ video, signal }) {
    const Constructor = detectorConstructor();
    const devices = camera();
    if (Constructor === null || devices === null) return null;

    const stream = await devices.getUserMedia({ video: { facingMode: 'environment' } });
    try {
      const deadline = Date.now() + SCAN_BUDGET_MS;
      video.srcObject = stream;
      const playing = await firstOf(
        video.play().then(() => true),
        signal,
        deadline
      );
      if (playing === null) return null;
      const detector = new Constructor({ formats: [CODE_FORMAT] });
      while (!signal.aborted && Date.now() < deadline) {
        const found = await firstOf(detector.detect(video), signal, deadline);
        if (found === null) return null;
        const text = found[0]?.rawValue;
        if (text !== undefined && text !== '') return text;
        if ((await firstOf(wait(FRAME_INTERVAL_MS), signal, deadline)) === null) return null;
      }
      return null;
    } finally {
      for (const track of stream.getTracks()) track.stop();
      video.srcObject = null;
    }
  },
};
