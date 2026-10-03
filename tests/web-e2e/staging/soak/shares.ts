/**
 * The two share folders of the soak, both read links: `soak/shared` holds one
 * long-running link whose read epoch never moves, and `soak/cycle` runs a
 * mint, claim, conversion and person revoke every night. A link URL is a bearer
 * capability: it lives in the owner ledger, in the owner's own vault, and a
 * summary or a log shows only {@link linkPrefix}.
 */

import { markerDate } from './grantee';
import { keyedLine, withKeyedLine, type Ledger } from './ledger';
import { DAY_MS } from './markers';
import { SoakFailure } from './reasons';

export const SHARED_FOLDER = 'shared';
export const CYCLE_FOLDER = 'cycle';

/** The dialog offers no "never" lifetime, so a deadline a century out stands in for it. */
export const LONG_RUNNING_MS = 36_500 * DAY_MS;

const SHARED_LINK = 'shared-link';

export interface Epochs {
  readonly read: bigint;
  readonly write: bigint;
}

export interface SharedLink {
  readonly readEpoch: bigint;
  readonly url: URL;
}

const EPOCHS = /read epoch (\d+) · write epoch (\d+)/;
const EPOCH = /^(0|[1-9]\d*)$/;

/** The epochs the share dialog row shows, as `// read epoch 3 · write epoch 1`. */
export function parseEpochs(text: string): Epochs {
  const match = EPOCHS.exec(text);
  if (match === null) throw new Error(`the epoch row reads "${text.trim()}"`);
  return { read: BigInt(match[1]!), write: BigInt(match[2]!) };
}

/** The long-running link the ledger holds, or `null` before its first mint. */
export function sharedLink(ledger: Ledger): SharedLink | null {
  const fields = keyedLine(ledger, SHARED_LINK);
  if (fields === null) return null;
  const [epoch, href] = fields;
  const url = fields.length === 2 && EPOCH.test(epoch!) ? linkUrl(href!) : null;
  if (url === null) throw new SoakFailure('ledger-unparsable', `the ${SHARED_LINK} line is bad`);
  return { readEpoch: BigInt(epoch!), url };
}

export function withSharedLink(ledger: Ledger, link: SharedLink): Ledger {
  if (link.readEpoch < 0n || linkUrl(link.url.href) === null) {
    throw new SoakFailure('ledger-unparsable', `the ${SHARED_LINK} line is not writable`);
  }
  return withKeyedLine(ledger, SHARED_LINK, [String(link.readEpoch), link.url.href]);
}

/** An invite link URL: a web address whose fragment carries the capability. */
function linkUrl(href: string): URL | null {
  let url: URL;
  try {
    url = new URL(href);
  } catch {
    return null;
  }
  const web = url.protocol === 'https:' || url.protocol === 'http:';
  return web && url.hash.length > 1 ? url : null;
}

/** The URL up to its fragment, which is the capability: what a summary may show. */
export function linkPrefix(url: URL): string {
  return `${url.origin}${url.pathname}#...`;
}

export function sharedEpochHeld(recorded: bigint, shown: bigint): void {
  if (shown !== recorded) {
    throw new SoakFailure(
      'shared-epoch-stepped',
      `the long-running link is at read epoch ${shown}, recorded ${recorded}`
    );
  }
}

/** A person revoke steps the read epoch by exactly one. */
export function cycleEpochStepped(before: bigint, after: bigint): void {
  if (after !== before + 1n) {
    throw new SoakFailure(
      'cycle-epoch-flat',
      `the revoke took the read epoch from ${before} to ${after}, not ${before + 1n}`
    );
  }
}

/** A share dialog element, as far as {@link grantsRead} looks at it; a `Locator` is one. */
export interface DialogMark {
  waitFor(options: { timeout: number }): Promise<void>;
  isVisible(): Promise<boolean>;
  textContent(): Promise<string | null>;
}

/** The parts of the share dialog that tell if its own read of the folder landed. */
export interface GrantsMarks {
  readonly people: DialogMark;
  readonly unavailable: DialogMark;
  /** The refusal the dialog shows where its read threw. */
  readonly error: DialogMark;
}

/**
 * Waits for the people table of the share dialog of `folder`. The dialog draws
 * the unavailable note until its own read lands, so only a table that does not
 * show in `timeout` is a read that failed.
 */
export async function grantsRead(
  marks: GrantsMarks,
  folder: string,
  timeout: number
): Promise<void> {
  try {
    await marks.people.waitFor({ timeout });
  } catch (error) {
    if (!(error instanceof Error) || error.name !== 'TimeoutError') throw error;
    const shown = (await marks.unavailable.isVisible())
      ? 'the unavailable note'
      : 'no people table';
    const refusal = (await marks.error.isVisible())
      ? `, refused: ${(await marks.error.textContent())?.trim()}`
      : '';
    throw new SoakFailure(
      'grants-unread',
      `the share dialog of ${folder}/ showed ${shown} after ${timeout / 1000} s${refusal}`
    );
  }
}

/** The newest markers `soak/shared` keeps, so a holder reads them all inside its budget. */
export const SHARED_MARKER_CAP = 30;

/** The days past `cap`, oldest first: what the owner moves to the bin. */
export function sharedOverCap(dates: readonly string[], cap: number): string[] {
  return dates.slice(0, Math.max(dates.length - cap, 0));
}

/** The days of the marker files among `names`, oldest first. */
export function markerDates(names: Iterable<string>): string[] {
  return [...names].flatMap((name) => markerDate(name) ?? []).sort();
}
