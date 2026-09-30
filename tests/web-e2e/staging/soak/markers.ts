/**
 * The owner's day markers: their names and bytes, the cap, the republish and
 * purge schedules, and the summary lines. A marker that left for the bin stays
 * in the ledger as a `binned <marker date> <bin day>` line until its purge is
 * proven.
 */

import { isUtcDay, type Ledger, type LedgerLine, type Marker } from './ledger';
import { SoakFailure } from './reasons';

/** The newest markers the owner vault keeps; the older ones go to the bin. */
export const MARKER_CAP = 90;

/** A marker older than this has passed its renewal point (EOL window 90, renewal at 30 left). */
export const REPUBLISH_AFTER_DAYS = 60;

/** `EOL_RENEW_THRESHOLD` in `crates/engine/src/net/eol.rs`. */
const RENEW_THRESHOLD_MS = 30 * 86_400_000;

const DAY_MS = 86_400_000;

const BINNED = /^binned (\S+) (\S+)$/;

export interface Binned {
  /** The day of the marker, which names its file. */
  readonly date: string;
  /** The UTC day the soak moved it to the bin. */
  readonly binnedOn: string;
}

export function markerFile(date: string): string {
  return `marker-${date}.txt`;
}

/** The bytes of a marker, a function of its day, so a read compares without a stored copy. */
export function markerBytes(date: string): Uint8Array {
  return new TextEncoder().encode(`cipherbox soak marker ${date}\n`);
}

/** Whole UTC days from `from` to `to`. */
export function ageDays(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / DAY_MS);
}

/** The ledger's markers, oldest first. */
export function byDate(list: readonly Marker[]): Marker[] {
  return [...list].sort((a, b) => a.date.localeCompare(b.date));
}

export function republishDue(marker: Marker, today: string): boolean {
  return ageDays(marker.date, today) > REPUBLISH_AFTER_DAYS;
}

/**
 * Whether a renewal set the EOL. A marker past {@link REPUBLISH_AFTER_DAYS}
 * has less than the renewal threshold left on its first EOL, so an EOL past
 * the threshold is a new one.
 */
export function freshValidity(validUntil: bigint | null, nowMs: number): boolean {
  return validUntil !== null && validUntil > BigInt(nowMs + RENEW_THRESHOLD_MS);
}

/** The markers past the cap, oldest first. */
export function overCap(list: readonly Marker[]): Marker[] {
  return byDate(list).slice(0, Math.max(list.length - MARKER_CAP, 0));
}

export function binnedMarkers(ledger: Ledger): Binned[] {
  return ledger.lines.flatMap((line) => {
    if (line.kind !== 'other' || !line.text.startsWith('binned ')) return [];
    const match = BINNED.exec(line.text);
    if (match === null || !isUtcDay(match[1]!) || !isUtcDay(match[2]!)) {
      throw new SoakFailure('ledger-unparsable', `"${line.text}" is not a binned line`);
    }
    return [{ date: match[1]!, binnedOn: match[2]! }];
  });
}

/** Swaps the marker lines of `dates` for binned lines of `today`. */
export function binMarkers(ledger: Ledger, dates: readonly string[], today: string): Ledger {
  const leaving = new Set(dates);
  const kept = ledger.lines.filter(
    (line) => line.kind !== 'marker' || !leaving.has(line.marker.date)
  );
  const binned = dates.map(
    (date): LedgerLine => ({ kind: 'other', text: `binned ${date} ${today}` })
  );
  return { lines: [...kept, ...binned] };
}

/** Drops the binned lines of `dates`, whose purge is proven. */
export function dropBinned(ledger: Ledger, dates: readonly string[]): Ledger {
  const purged = new Set(dates);
  return {
    lines: ledger.lines.filter(
      (line) =>
        line.kind !== 'other' ||
        !line.text.startsWith('binned ') ||
        !purged.has(line.text.split(' ')[1]!)
    ),
  };
}

/**
 * Whether the purge of `entry` must have landed by a run on `today`. A night
 * runs at no fixed time, so the purge falls due on the first day after the
 * retention ends, when the move is surely older than the retention.
 */
export function purgeDue(entry: Binned, retentionDays: number, today: string): boolean {
  return ageDays(entry.binnedOn, today) > retentionDays;
}

export interface SequenceReading {
  readonly date: string;
  readonly ledger: number;
  readonly resolved: bigint;
}

/** The oldest marker that opened, and its age: the proven horizon. */
export function oldestMarkerLine(oldest: Marker | undefined, today: string): string {
  if (oldest === undefined) return 'no marker yet';
  return `${oldest.date}, ${ageDays(oldest.date, today)} days old, opened from a cold client`;
}

export function binLine(binned: number, purged: number, retentionDays: number): string {
  return `${purged} purged when due, ${binned - purged} waiting; retention ${retentionDays} days`;
}

export function sequencesLine(readings: readonly SequenceReading[]): string {
  if (readings.length === 0) return 'no marker yet';
  const advanced = readings.filter((reading) => reading.resolved > BigInt(reading.ledger));
  const newest = readings.reduce((a, b) => (a.date > b.date ? a : b));
  return (
    `${readings.length} names at or above the ledger, ${advanced.length} advanced by a renewal; ` +
    `newest ${newest.date} at ${newest.resolved} (ledger ${newest.ledger})`
  );
}
