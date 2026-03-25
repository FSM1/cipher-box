import { useEffect } from 'react';
import { useAuthStore } from '../../stores/auth.store';
import { useQuotaStore } from '../../stores/quota.store';
import { formatBytes } from '../../utils/format';

/**
 * Storage quota indicator component.
 * Shows storage usage with a progress bar and text.
 * Fetches current quota from the backend on mount.
 * Displays advisory badge for BYO users.
 */
export function StorageQuota() {
  const { usedBytes, limitBytes, advisory, fetchQuota } = useQuotaStore();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);

  // Fetch quota from backend once authenticated so the display reflects
  // actual usage (e.g. files uploaded in previous sessions).
  // Guarded by isAuthenticated to avoid firing before session restoration
  // completes — an unauthenticated request would race with the refresh
  // token flow and could trigger an accidental logout.
  useEffect(() => {
    if (isAuthenticated) {
      fetchQuota();
    }
  }, [fetchQuota, isAuthenticated]);

  // Calculate percentage (avoid division by zero)
  const percentage = limitBytes > 0 ? (usedBytes / limitBytes) * 100 : 0;

  return (
    <div className="storage-quota" data-testid="storage-quota">
      <div className="storage-quota-bar">
        <div className="storage-quota-fill" style={{ width: `${Math.min(percentage, 100)}%` }} />
      </div>
      <div className="storage-quota-info">
        <span className="storage-quota-text">
          {formatBytes(usedBytes)} / {formatBytes(limitBytes)}
        </span>
        {advisory && <span className="storage-quota-advisory-badge">ADVISORY</span>}
      </div>
      {advisory && (
        <p className="storage-quota-advisory-hint">
          {'storage is managed by your node. this total is approximate.'}
        </p>
      )}
    </div>
  );
}
