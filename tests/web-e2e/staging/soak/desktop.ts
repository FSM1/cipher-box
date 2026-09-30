/**
 * The leg markers in the grantee vault, in the shape the desktop legs use
 * (`tests/desktop-e2e/src/soak/plan.ts`, not landed yet): each leg writes
 * `soak/desktop/<leg>/marker-<date>.txt` with the bytes of `markerBytes`
 * and adds the line `marker <leg> <date>` to `soak/desktop/ledger.txt`. A mount
 * shows no IPNS name or sequence, so the line carries neither. The functions
 * here keep the names and logic of that module, so the one that lands second
 * imports them in place of this copy.
 */

import { isUtcDay, type Ledger, type LedgerLine } from './ledger';
import { SoakFailure } from './reasons';

export type DesktopLeg = 'macos' | 'linux' | 'windows';
export type MarkerLeg = DesktopLeg | 'web';

export const MARKER_LEGS: readonly MarkerLeg[] = ['macos', 'linux', 'windows', 'web'];
export const DESKTOP_LEGS: readonly DesktopLeg[] = ['macos', 'linux', 'windows'];

const LINE = /^marker (\S+) (\S+)$/;
const MARKER_FILE = /^marker-(\d{4}-\d{2}-\d{2})\.txt$/;

export interface LegMarker {
  readonly leg: MarkerLeg;
  readonly date: string;
}

/** The ledger line of one leg marker. Refuses a line that {@link legMarkers} would reject. */
export function ledgerLine(marker: LegMarker): string {
  const line = `marker ${marker.leg} ${marker.date}`;
  if (parseLine(line) === null) {
    throw new SoakFailure(
      'ledger-unparsable',
      `the ${marker.leg} marker of ${marker.date} is not writable`
    );
  }
  return line;
}

/** The leg markers the ledger lists. A `marker ` line of another shape is `ledger-unparsable`. */
export function legMarkers(ledger: Ledger): LegMarker[] {
  return ledger.lines.flatMap((line) => {
    if (line.kind !== 'other' || !line.text.startsWith('marker ')) return [];
    const marker = parseLine(line.text);
    if (marker === null) {
      throw new SoakFailure('ledger-unparsable', `"${line.text}" is not a leg marker line`);
    }
    return [marker];
  });
}

/** Adds the line of `marker` once: a second run on one day leaves the ledger as it is. */
export function recordMarker(ledger: Ledger, marker: LegMarker): Ledger {
  const text = ledgerLine(marker);
  if (ledger.lines.some((line) => line.kind === 'other' && line.text === text)) return ledger;
  const added: LedgerLine = { kind: 'other', text };
  return { lines: [...ledger.lines, added] };
}

/** The day a listed file names, or `null` for a file that is not a marker. */
export function markerDate(fileName: string): string | null {
  const match = MARKER_FILE.exec(fileName);
  return match !== null && isUtcDay(match[1]!) ? match[1]! : null;
}

/**
 * What a leg must read: every marker of the other legs, from the ledger and
 * from the folder listings both, so a marker that lost its line and a line that
 * lost its marker each count.
 */
export function markersToRead(
  ledger: Ledger,
  listed: Readonly<Partial<Record<MarkerLeg, readonly string[]>>>,
  self: MarkerLeg
): LegMarker[] {
  const found = new Map<string, LegMarker>();
  const add = (marker: LegMarker): void => {
    if (marker.leg !== self) found.set(`${marker.leg} ${marker.date}`, marker);
  };
  legMarkers(ledger).forEach(add);
  for (const leg of MARKER_LEGS) {
    for (const name of listed[leg] ?? []) {
      const date = markerDate(name);
      if (date !== null) add({ leg, date });
    }
  }
  return [...found.values()].sort(
    (a, b) =>
      MARKER_LEGS.indexOf(a.leg) - MARKER_LEGS.indexOf(b.leg) || a.date.localeCompare(b.date)
  );
}

/** The summary fact of what a leg read, one count per leg. */
export function readLine(read: readonly LegMarker[]): string {
  if (read.length === 0) return 'no marker of another leg yet';
  return MARKER_LEGS.flatMap((leg) => {
    const count = read.filter((marker) => marker.leg === leg).length;
    return count === 0 ? [] : [`${leg} ${count}`];
  }).join(', ');
}

function parseLine(text: string): LegMarker | null {
  const match = LINE.exec(text);
  if (match === null) return null;
  const leg = MARKER_LEGS.find((known) => known === match[1]);
  return leg !== undefined && isUtcDay(match[2]!) ? { leg, date: match[2]! } : null;
}
