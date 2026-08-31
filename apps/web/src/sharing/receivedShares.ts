/**
 * How the engine's verdict on a received share reads to the member. The engine
 * classifies (`crates/engine/src/grants/revocation.rs`); this weighs it and
 * puts it in words, and coins no second name for a class the engine already
 * names.
 *
 * `warning` is the distinct trust class the UI state law keeps off the
 * staleness ladder (blueprint/web-client.md "Staleness ladder rendering"), so a
 * removal never reads as "behind".
 */

import type { ReceivedShareResolution } from '@cipherbox/client';

type StandingTone = 'ok' | 'pending' | 'warning';

/** One share's standing, as a row renders it. */
export interface ReceivedShareStanding {
  readonly tone: StandingTone;
  readonly label: string;
}

/**
 * A `Record` over the closed union, so a class the engine gains breaks this
 * build rather than falling through to a guess at render time.
 */
const CLASSES: Record<ReceivedShareResolution, ReceivedShareStanding> = {
  granted: { tone: 'ok', label: 'granted' },
  'revocation-signal': { tone: 'warning', label: 'the owner removed you from this folder' },
  unresolvable: {
    tone: 'pending',
    label: 'the owner record did not resolve — absent, not a removal',
  },
  'epoch-lag': { tone: 'pending', label: 'behind the owner record — a sweep is pending' },
};

/** No pass has resolved this share yet, which is not "still granted". */
const UNREAD: ReceivedShareStanding = {
  tone: 'pending',
  label: 'no check has reached this folder yet',
};

/** Fail closed: a class this build cannot name never renders as one that stands. */
const UNRECOGNISED: ReceivedShareStanding = {
  tone: 'warning',
  label: 'this build does not recognise the standing the engine reported',
};

export function shareStanding(resolution: ReceivedShareResolution | null): ReceivedShareStanding {
  if (resolution === null) return UNREAD;
  // `hasOwn`, so any key this build does not name fails closed.
  return Object.hasOwn(CLASSES, resolution) ? CLASSES[resolution] : UNRECOGNISED;
}
