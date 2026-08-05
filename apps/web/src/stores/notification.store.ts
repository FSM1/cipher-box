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

/** Distinct keys accumulate unbounded otherwise; the newest warning wins. */
const MAX_NOTICES = 5;

let notices: readonly Notice[] = Object.freeze([]);
const listeners = new Set<() => void>();

function publish(next: readonly Notice[]): void {
  // Frozen: a consumer must not mutate what the UI is already rendering.
  notices = Object.freeze(next);
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
    if (notices.length > 0) publish([]);
  },
};
