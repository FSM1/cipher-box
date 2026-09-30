/**
 * The pure parts of the desktop soak leg: the leg names, the marker paths, the
 * grantee ledger lines, the time budgets, and the environment the remote-stack
 * mode reads. The marker name and bytes and the ledger file format are the web
 * soak's own, so both sides read what the other writes.
 *
 * The grantee ledger is `soak/desktop/ledger.txt`. Each marker a leg writes adds
 * one `marker <leg> <date>` line, and the marker itself is
 * `soak/desktop/<leg>/marker-<date>.txt`.
 */

import { isUtcDay, type Ledger, type LedgerLine } from '../../../web-e2e/staging/soak/ledger';
import { markerFile } from '../../../web-e2e/staging/soak/markers';
import { SoakFailure } from '../../../web-e2e/staging/soak/reasons';
import { PRODUCTION_PROFILE, deadlines, type Deadlines, type SyncTimingProfile } from '../profile';

export type DesktopLeg = 'macos' | 'linux' | 'windows';
export type MarkerLeg = DesktopLeg | 'web';

export const MARKER_LEGS: readonly MarkerLeg[] = ['macos', 'linux', 'windows', 'web'];

/** The grantee's desktop folder, from the vault root. The web bootstrap builds it. */
export const DESKTOP_FOLDER: readonly string[] = ['soak', 'desktop'];
export const LEDGER_FILE = 'ledger.txt';

export const LOGIN_SECRET_ENV = 'SOAK_GRANTEE_LOGIN_SECRET';
export const API_URL_ENV = 'VITE_API_URL';
export const ROUTING_ENDPOINTS_ENV = 'VITE_ROUTING_ENDPOINTS';

const LINE = /^marker (\S+) (\S+)$/;
const MARKER_FILE = /^marker-(\d{4}-\d{2}-\d{2})\.txt$/;

export interface LegMarker {
  readonly leg: MarkerLeg;
  readonly date: string;
}

export function legOf(platform: NodeJS.Platform): DesktopLeg {
  if (platform === 'darwin') return 'macos';
  if (platform === 'linux') return 'linux';
  if (platform === 'win32') return 'windows';
  throw new Error(`no desktop soak leg runs on ${platform}`);
}

export function markerPath(marker: LegMarker): string[] {
  return [...DESKTOP_FOLDER, marker.leg, markerFile(marker.date)];
}

export function ledgerPath(): string[] {
  return [...DESKTOP_FOLDER, LEDGER_FILE];
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
  self: DesktopLeg
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

/** The time each step of a leg gets, so a slow night fails with the reason of its step. */
export interface SoakBudgets {
  /** The API serves a login, the shell writes its control file, and the mount opens. */
  signInMs: number;
  /** The grantee ledger opens through the mount. */
  ledgerMs: number;
  /** The reads of the other legs' markers, before the per-marker share. */
  readBaseMs: number;
  readPerMarkerMs: number;
  /** Today's marker and its ledger line land on the writer's mount. */
  writeMs: number;
  /** A cold mount serves both, after its own sign-in. */
  publishMs: number;
}

/** Multiples of the poll cadence, so the 30-second production cadence paces no step past its budget. */
export function soakBudgets(profile: SyncTimingProfile = PRODUCTION_PROFILE): SoakBudgets {
  const tick = profile.pollCadenceMs;
  return {
    signInMs: 20 * tick,
    ledgerMs: 10 * tick,
    readBaseMs: 10 * tick,
    readPerMarkerMs: Math.round(tick / 10),
    writeMs: 10 * tick,
    publishMs: 20 * tick,
  };
}

export function readBudget(budgets: SoakBudgets, markers: number): number {
  return budgets.readBaseMs + markers * budgets.readPerMarkerMs;
}

/** The instance waits of a leg: each start wait fits inside the sign-in budget. */
export function legDeadlines(
  budgets: SoakBudgets,
  profile: SyncTimingProfile = PRODUCTION_PROFILE
): Deadlines {
  return {
    ...deadlines(profile),
    apiReadyMs: budgets.signInMs,
    controlFileMs: budgets.signInMs,
    mountMs: budgets.signInMs,
  };
}

type Env = Readonly<Record<string, string | undefined>>;

/**
 * The grantee login secret as the host reads it: 64 lowercase hex characters.
 * No refusal repeats the value.
 */
export function loginSecret(env: Env): string {
  const raw = env[LOGIN_SECRET_ENV]?.trim();
  if (raw === undefined || raw === '') throw new Error(`${LOGIN_SECRET_ENV} is not set`);
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) {
    throw new Error(`${LOGIN_SECRET_ENV} is not 32 bytes of hex`);
  }
  return raw.replace(/^0x/, '').toLowerCase();
}

export interface RemoteStack {
  readonly apiUrl: string;
  readonly routingEndpoints: readonly string[];
}

/**
 * The deployment the host was built against, from the variables its build
 * read. An endpoint is https, or http on a loopback host for a local run.
 */
export function remoteStack(env: Env): RemoteStack {
  const apiUrl = endpoint(API_URL_ENV, env[API_URL_ENV]);
  const routingEndpoints = (env[ROUTING_ENDPOINTS_ENV] ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry !== '')
    .map((entry) => endpoint(ROUTING_ENDPOINTS_ENV, entry));
  if (routingEndpoints.length === 0) {
    throw new Error(`${ROUTING_ENDPOINTS_ENV} must list at least one routing endpoint`);
  }
  return { apiUrl, routingEndpoints };
}

const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]']);

function endpoint(name: string, raw: string | undefined): string {
  const value = raw?.trim();
  if (value === undefined || value === '') throw new Error(`${name} is not set`);
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} holds a value that is not a URL`);
  }
  if (url.protocol === 'https:' || (url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
    return value;
  }
  throw new Error(`${name} must be an https URL, or http on a loopback host`);
}
