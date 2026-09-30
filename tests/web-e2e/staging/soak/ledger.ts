/**
 * The soak ledger: one text file in the vault, read and rewritten in place
 * through the text editor. The first line is the header; each marker line is
 * `<date> <marker IPNS name> <record sequence at write time>`. A line of any other
 * shape is kept as it is, so a later suite can add lines that this one carries
 * through a rewrite.
 */

import { SoakFailure } from './reasons';

export const LEDGER_HEADER = 'cipherbox-soak-ledger 1';

export interface Marker {
  /** The UTC day the marker was written, as `YYYY-MM-DD`. */
  readonly date: string;
  readonly ipnsName: string;
  readonly sequence: number;
}

export type LedgerLine =
  | { readonly kind: 'marker'; readonly marker: Marker }
  | { readonly kind: 'other'; readonly text: string };

export interface Ledger {
  readonly lines: readonly LedgerLine[];
}

export function emptyLedger(): Ledger {
  return { lines: [] };
}

export function markers(ledger: Ledger): Marker[] {
  return ledger.lines.flatMap((line) => (line.kind === 'marker' ? [line.marker] : []));
}

/** Parses the file text. A bad header or a bad marker line is `ledger-unparsable`. */
export function parseLedger(text: string): Ledger {
  const [header, ...rest] = text.replace(/\r\n/g, '\n').replace(/\n$/, '').split('\n');
  if (header !== LEDGER_HEADER) {
    throw new SoakFailure('ledger-unparsable', `the first line is not "${LEDGER_HEADER}"`);
  }
  return {
    lines: rest.map((line, index): LedgerLine => {
      if (!/^\d/.test(line)) return { kind: 'other', text: line };
      const marker = parseMarkerLine(line);
      if (marker === null) {
        throw new SoakFailure('ledger-unparsable', `line ${index + 2} is not a marker line`);
      }
      return { kind: 'marker', marker };
    }),
  };
}

export function formatLedger(ledger: Ledger): string {
  const body = ledger.lines.map((line) => {
    if (line.kind === 'marker') return markerText(line.marker);
    if (/^\d/.test(line.text) || line.text.includes('\n')) {
      throw new SoakFailure('ledger-unparsable', 'a kept line would read back as another line');
    }
    return line.text;
  });
  return [LEDGER_HEADER, ...body].join('\n') + '\n';
}

export function appendMarker(ledger: Ledger, marker: Marker): Ledger {
  markerText(marker);
  return { lines: [...ledger.lines, { kind: 'marker', marker }] };
}

/** The marker line. Refuses a marker that {@link parseLedger} would reject. */
function markerText(marker: Marker): string {
  const line = `${marker.date} ${marker.ipnsName} ${marker.sequence}`;
  if (parseMarkerLine(line) === null) {
    throw new SoakFailure('ledger-unparsable', `the marker of ${marker.date} is not writable`);
  }
  return line;
}

function parseMarkerLine(line: string): Marker | null {
  const fields = line.split(' ');
  if (fields.length !== 3) return null;
  const [date, ipnsName, sequence] = fields as [string, string, string];
  if (!isUtcDay(date) || !/^[A-Za-z0-9]+$/.test(ipnsName) || !/^(0|[1-9]\d*)$/.test(sequence)) {
    return null;
  }
  const value = Number(sequence);
  return Number.isSafeInteger(value) ? { date, ipnsName, sequence: value } : null;
}

/** A real calendar day as `YYYY-MM-DD`. */
export function isUtcDay(value: string): boolean {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const parsed = new Date(`${value}T00:00:00Z`);
  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === value;
}

/** The UTC day of `now`, as a ledger date. */
export function utcDay(now: Date): string {
  return now.toISOString().slice(0, 10);
}
