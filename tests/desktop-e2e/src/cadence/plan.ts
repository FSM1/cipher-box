/**
 * The pure parts of the mount-cadence probe: when each mount starts, and what
 * the run concludes.
 *
 * A mount that starts within about 150 s of a machine's first FUSE-T mount,
 * under a name an earlier mount used, can fail to resolve its own server. The
 * probe mounts at a fixed cadence across that span, so a run either crosses
 * the window or reports that it did not.
 */

export const SPAN_ENV = 'CIPHERBOX_CADENCE_SPAN_MS';
export const EVERY_ENV = 'CIPHERBOX_CADENCE_EVERY_MS';

const DEFAULT_SPAN_MS = 160_000;
const DEFAULT_EVERY_MS = 5_000;

export interface Cadence {
  /** The latest offset from the first mount at which a mount still starts. */
  spanMs: number;
  /** The interval between two mount starts. */
  everyMs: number;
}

export function cadenceOf(env: Record<string, string | undefined>): Cadence {
  return {
    spanMs: positive(env[SPAN_ENV], DEFAULT_SPAN_MS, SPAN_ENV),
    everyMs: positive(env[EVERY_ENV], DEFAULT_EVERY_MS, EVERY_ENV),
  };
}

function positive(value: string | undefined, fallback: number, name: string): number {
  if (value === undefined || value === '') return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive whole number of milliseconds, not "${value}"`);
  }
  return parsed;
}

/**
 * The offset of the next mount start, or `null` once the span is over. A mount
 * that ran long gives up the slots it overran rather than starting late.
 */
export function nextStart(cadence: Cadence, elapsedMs: number): number | null {
  const slot = Math.ceil(elapsedMs / cadence.everyMs) * cadence.everyMs;
  return slot <= cadence.spanMs ? slot : null;
}

export interface MountResult {
  /** The start offset from the first mount. */
  offsetMs: number;
  outcome: 'live' | 'failed';
  /** How long the start took to reach its outcome. */
  tookMs: number;
  detail: string;
}

/** One line of the run log. */
export function line(result: MountResult): string {
  const at = (result.offsetMs / 1000).toFixed(1);
  return `+${at}s ${result.outcome} after ${result.tookMs}ms: ${result.detail}`;
}

/** The failures, or a refusal of a run too short to have crossed the window. */
export function verdict(cadence: Cadence, results: readonly MountResult[]): MountResult[] {
  const last = results.at(-1)?.offsetMs ?? 0;
  if (last + cadence.everyMs <= cadence.spanMs) {
    throw new Error(`the last mount started at ${last}ms, short of the ${cadence.spanMs}ms span`);
  }
  return results.filter((result) => result.outcome === 'failed');
}
