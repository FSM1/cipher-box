import { useSyncStore } from '../../stores/sync.store';

/**
 * Sync status indicator for header.
 *
 * Per CONTEXT.md:
 * - Spinning icon during sync
 * - Checkmark when done
 * - Warning icon on sync failure (subtle, cached data remains visible)
 * - No timestamp display
 */
export function SyncIndicator() {
  const { status } = useSyncStore();

  // Icon and title based on status
  const getIcon = () => {
    switch (status) {
      case 'syncing':
        return (
          <svg
            className="sync-indicator-icon sync-indicator-icon--spinning"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
        );
      case 'success':
        return (
          <svg
            className="sync-indicator-icon sync-indicator-icon--success"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <polyline points="20 6 9 17 4 12" />
          </svg>
        );
      case 'error':
        return (
          <svg
            className="sync-indicator-icon sync-indicator-icon--error"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="12" y1="8" x2="12" y2="12" />
            <line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
        );
      default: // idle
        return (
          <svg
            className="sync-indicator-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            aria-hidden="true"
          >
            <path d="M21 12a9 9 0 1 1-6.219-8.56" />
          </svg>
        );
    }
  };

  const getTitle = () => {
    switch (status) {
      case 'syncing':
        return 'Syncing...';
      case 'success':
        return 'Synced';
      case 'error':
        return 'Sync failed';
      default:
        return 'Sync';
    }
  };

  return (
    <div className="sync-indicator" title={getTitle()} role="status" aria-live="polite">
      {getIcon()}
      <span className="sr-only">{getTitle()}</span>
    </div>
  );
}
