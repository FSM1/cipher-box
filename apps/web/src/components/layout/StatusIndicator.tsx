import { useStaleness } from '../../engine/useStaleness';
import { useSnapshotStore } from '../../providers/EngineProvider';

/** The staleness ladder's rungs, as the footer renders them (#33 D4). */
const RUNGS = {
  fresh: { label: 'synced', className: 'status-indicator--fresh' },
  reconciling: { label: 'syncing...', className: 'status-indicator--reconciling' },
  stale: { label: 'stale', className: 'status-indicator--stale' },
  offline: { label: 'offline', className: 'status-indicator--offline' },
} as const;

/** Where the vault sits on the staleness ladder, and the manual refresh. */
export function StatusIndicator() {
  const staleness = useStaleness();
  const store = useSnapshotStore();
  const rung = RUNGS[staleness];

  return (
    <button
      type="button"
      className={`status-indicator ${rung.className}`}
      data-testid="status-indicator"
      data-staleness={staleness}
      title="Refresh now"
      onClick={() => store.refresh()}
    >
      <span className="status-indicator-dot" aria-hidden="true" />
      {rung.label}
    </button>
  );
}
