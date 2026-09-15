/**
 * The camera leg of a contact exchange: a code offered as a QR, read into the
 * same text the paste field takes. This decodes a transport encoding and
 * nothing else — the binding verify stays the engine's
 * (blueprint/engine.md "Contact import").
 */

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

type DetectorConstructor = new (init: { formats: string[] }) => Detector;

interface ScanTarget {
  /** The preview the member aims; also the frame source the detector reads. */
  video: HTMLVideoElement;
  /** Aborted when the member leaves the scan, which stops the camera. */
  signal: AbortSignal;
}

export interface ContactScanner {
  /** Whether this browser can read a code from the camera at all. */
  supported(): boolean;
  /**
   * The text of the first frame that carries a code, or `null` when the budget
   * passed or the member left. It rejects when the camera itself is refused.
   */
  scan(target: ScanTarget): Promise<string | null>;
}

function detectorConstructor(): DetectorConstructor | null {
  const candidate = (globalThis as { BarcodeDetector?: DetectorConstructor }).BarcodeDetector;
  return typeof candidate === 'function' ? candidate : null;
}

function camera(): MediaDevices | null {
  const devices = globalThis.navigator?.mediaDevices;
  return typeof devices?.getUserMedia === 'function' ? devices : null;
}

function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** The browser seam. Tests pass their own `ContactScanner` instead. */
export const browserContactScanner: ContactScanner = {
  supported: () => detectorConstructor() !== null && camera() !== null,

  async scan({ video, signal }) {
    const Constructor = detectorConstructor();
    const devices = camera();
    if (Constructor === null || devices === null) return null;

    const stream = await devices.getUserMedia({ video: { facingMode: 'environment' } });
    try {
      video.srcObject = stream;
      await video.play();
      const detector = new Constructor({ formats: ['qr_code'] });
      const deadline = Date.now() + SCAN_BUDGET_MS;
      while (!signal.aborted && Date.now() < deadline) {
        const found = await detector.detect(video);
        const text = found[0]?.rawValue;
        if (text !== undefined && text !== '') return text;
        await wait(FRAME_INTERVAL_MS);
      }
      return null;
    } finally {
      for (const track of stream.getTracks()) track.stop();
      video.srcObject = null;
    }
  },
};
