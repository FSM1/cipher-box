/**
 * The cross-platform markers in the grantee vault. Each desktop leg writes
 * `soak/desktop/<os>/marker-<date>.txt` through its mount, the web leg writes
 * `soak/desktop/web/marker-<date>.txt`, and each adds the line
 * `marker <os> <date>` to `soak/desktop/ledger.txt`. The other legs read them
 * the next night. A mount shows no record sequence, so the line carries none.
 */

import { isUtcDay, type Ledger, type LedgerLine } from './ledger';
import { SoakFailure } from './reasons';

export const DESKTOP_FOLDER = 'desktop';

export const OS_LEGS = ['macos', 'linux', 'windows'] as const;

export type MarkerOrigin = (typeof OS_LEGS)[number] | 'web';

const ORIGINS: readonly string[] = [...OS_LEGS, 'web'];

export interface DesktopMarker {
  readonly origin: MarkerOrigin;
  /** The UTC day the leg wrote it, as `YYYY-MM-DD`. */
  readonly date: string;
}

/** The bytes of a marker, a function of its origin and day, so a read compares without a copy. */
export function desktopMarkerBytes(marker: DesktopMarker): Uint8Array {
  return new TextEncoder().encode(`cipherbox soak marker ${marker.origin} ${marker.date}\n`);
}

function markerLine(marker: DesktopMarker): string {
  return `marker ${marker.origin} ${marker.date}`;
}

function parseMarkerLine(line: LedgerLine): DesktopMarker | null {
  if (line.kind !== 'other' || !line.text.startsWith('marker ')) return null;
  const [, origin, date, ...rest] = line.text.split(' ');
  if (rest.length > 0 || !ORIGINS.includes(origin!) || !isUtcDay(date ?? '')) {
    throw new SoakFailure('ledger-unparsable', `"${line.text}" is not a desktop marker line`);
  }
  return { origin: origin as MarkerOrigin, date: date! };
}

export function desktopMarkers(ledger: Ledger): DesktopMarker[] {
  return ledger.lines.flatMap((line) => parseMarkerLine(line) ?? []);
}

/** Appends the line of `marker`, once. */
export function appendDesktopMarker(ledger: Ledger, marker: DesktopMarker): Ledger {
  const line: LedgerLine = { kind: 'other', text: markerLine(marker) };
  if (parseMarkerLine(line) === null) {
    throw new SoakFailure('ledger-unparsable', `"${line.text}" is not writable`);
  }
  const held = desktopMarkers(ledger).some(
    (known) => known.origin === marker.origin && known.date === marker.date
  );
  return held ? ledger : { lines: [...ledger.lines, line] };
}

/** Per OS leg: how many of its markers opened in the browser, and the newest. */
export function osMarkersLine(opened: readonly DesktopMarker[]): string {
  return OS_LEGS.map((os) => {
    const dates = opened
      .filter((marker) => marker.origin === os)
      .map((marker) => marker.date)
      .sort();
    return dates.length === 0 ? `${os} none` : `${os} ${dates.length}, newest ${dates.at(-1)}`;
  }).join('; ');
}
