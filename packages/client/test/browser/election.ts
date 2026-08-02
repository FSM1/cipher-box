/**
 * Waits out the engine-lock election for the tab-leadership and media browser
 * harnesses, so a caller's role assertion reads a decided outcome rather than
 * `EngineClient`'s pre-election `follower` default.
 */
import type { EngineClient } from '../../src/engineClient.js';

const POLL_MS = 10;
const TIMEOUT_MS = 10_000;

/** This tab's Web Locks client id, read back off a lock only this tab can hold. */
async function ownClientId(): Promise<string> {
  const probe = `cb-election-probe-${crypto.randomUUID()}`;
  let mine: string | undefined;
  await navigator.locks.request(probe, async () => {
    const { held = [] } = await navigator.locks.query();
    mine = held.find((lock) => lock.name === probe)?.clientId;
  });
  if (mine === undefined) throw new Error('navigator.locks.query() reported no client id');
  return mine;
}

/**
 * Leader is `currentRole()`, which promotion flips only once the engine worker
 * is live; follower is this tab's *own* request queued behind another tab's held
 * lock. Matching the client id keeps a leader's momentarily-pending request from
 * reading as a follower's.
 */
export async function awaitElection(
  client: EngineClient,
  lockName: string
): Promise<'leader' | 'follower'> {
  const mine = await ownClientId();
  const deadline = Date.now() + TIMEOUT_MS;
  for (;;) {
    if (client.currentRole() === 'leader') return 'leader';
    const { held = [], pending = [] } = await navigator.locks.query();
    if (
      held.some((lock) => lock.name === lockName && lock.clientId !== mine) &&
      pending.some((lock) => lock.name === lockName && lock.clientId === mine)
    ) {
      return 'follower';
    }
    if (Date.now() > deadline) throw new Error(`engine-lock election never settled: ${lockName}`);
    await new Promise((resolve) => setTimeout(resolve, POLL_MS));
  }
}
