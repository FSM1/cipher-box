import { useStaleness } from '../../engine/useStaleness';

/** The staleness ladder's rungs, as the footer renders them (#33 D4). */
const RUNGS = {
  fresh: { label: 'synced', className: 'status-indicator--fresh' },
  reconciling: { label: 'syncing...', className: 'status-indicator--reconciling' },
  stale: { label: 'stale', className: 'status-indicator--stale' },
  offline: { label: 'offline', className: 'status-indicator--offline' },
} as const;

/** Where the vault sits on the staleness ladder. */
export function StatusIndicator() {
  const staleness = useStaleness();
  const rung = RUNGS[staleness];

  return (
    <span
      className={`status-indicator ${rung.className}`}
      data-testid="status-indicator"
      data-staleness={staleness}
    >
      <span className="status-indicator-dot" aria-hidden="true" />
      {rung.label}
    </span>
  );
}
