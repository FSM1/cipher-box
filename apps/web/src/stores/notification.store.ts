/**
 * The warning-notice surface: a trust violation or a withheld-update escalation
 * renders here, as its own class, and never on the staleness ladder
 * (blueprint/web-client.md "Staleness ladder rendering").
 *
 * Memory only, and cleared when the engine that raised the notices goes away —
 * a notice names the scope it came from, so it must not outlive that session.
 */

/** One standing warning. `key` is its identity: a repeat collapses onto it. */
export interface Notice {
  readonly key: string;
  readonly message: string;
}

/**
 * The engine emits per resolve attempt, so an unreachable scope raises the same
 * warning on every tick; the cap bounds what an event storm can accumulate.
 */
const MAX_NOTICES = 5;

const EMPTY: readonly Notice[] = Object.freeze([]);

let notices: readonly Notice[] = EMPTY;
const listeners = new Set<() => void>();

function publish(next: readonly Notice[]): void {
  // Frozen and identity-compared: `useSyncExternalStore` bails out on identity,
  // and a consumer must not be able to mutate what the UI is rendering.
  notices = next.length === 0 ? EMPTY : Object.freeze(next);
  for (const listener of listeners) listener();
}

export const notificationStore = {
  subscribe(onStoreChange: () => void): () => void {
    listeners.add(onStoreChange);
    return () => listeners.delete(onStoreChange);
  },
  getState: (): readonly Notice[] => notices,
  /** Raises `message` under `key`, or does nothing if that key already stands. */
  warn(key: string, message: string): void {
    if (notices.some((notice) => notice.key === key)) return;
    publish([...notices, { key, message }].slice(-MAX_NOTICES));
  },
  dismiss(key: string): void {
    const next = notices.filter((notice) => notice.key !== key);
    if (next.length !== notices.length) publish(next);
  },
  clear(): void {
    if (notices.length > 0) publish(EMPTY);
  },
};
