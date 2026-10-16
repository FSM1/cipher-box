/**
 * The warning-notice surface: a trust violation or a withheld-update escalation
 * renders here, as its own class, and never on the staleness ladder
 * (blueprint/web-client.md "Staleness ladder rendering"). A plain notice that
 * outlives the screen that raised it, such as a sign-in that could not save
 * this device, renders here too.
 *
 * Memory only, and cleared when the engine that raised the notices goes away —
 * a notice names the scope it came from, so it must not outlive that session.
 */

/** A step the reader can take from the notice itself. */
export interface NoticeAction {
  readonly label: string;
  run(): Promise<void>;
}

/** One standing warning. `key` is its identity: a repeat collapses onto it. */
export interface Notice {
  readonly key: string;
  readonly message: string;
  readonly action?: NoticeAction;
  /** A minor notice is evicted before any other, so a burst of them cannot push a warning out. */
  readonly minor?: boolean;
}

/** Distinct keys accumulate unbounded otherwise; the newest warning wins. */
const MAX_NOTICES = 5;

let notices: readonly Notice[] = Object.freeze([]);
const listeners = new Set<() => void>();

/** Adds `notice` unless its key stands; past the bound, evicts the oldest minor notice, else the oldest. */
function admit(notice: Notice): void {
  if (notices.some((standing) => standing.key === notice.key)) return;
  const next = [...notices, notice];
  if (next.length > MAX_NOTICES) {
    const minor = next.findIndex((standing) => standing.minor);
    const evicted = minor === -1 ? 0 : minor;
    if (next[evicted] === notice) return;
    next.splice(evicted, 1);
  }
  publish(next);
}

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
  warn(key: string, message: string, action?: NoticeAction): void {
    admit({ key, message, action });
  },
  /** As `warn`, for a notice that must never evict one raised by `warn`. */
  warnMinor(key: string, message: string): void {
    admit({ key, message, minor: true });
  },
  dismiss(key: string): void {
    const next = notices.filter((notice) => notice.key !== key);
    if (next.length !== notices.length) publish(next);
  },
  clear(): void {
    if (notices.length > 0) publish([]);
  },
};
