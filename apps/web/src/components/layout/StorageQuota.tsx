import { useQuotaStore } from '../../stores/quota.store';

/**
 * Format bytes to human-readable string.
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const value = bytes / Math.pow(k, i);

  // Use 1 decimal place for larger units
  return `${value.toFixed(i > 1 ? 1 : 0)} ${units[i]}`;
}

/**
 * Storage quota indicator component.
 * Shows storage usage with a progress bar and text.
 */
export function StorageQuota() {
  const { usedBytes, limitBytes } = useQuotaStore();

  // Calculate percentage (avoid division by zero)
  const percentage = limitBytes > 0 ? (usedBytes / limitBytes) * 100 : 0;

  return (
    <div className="storage-quota" data-testid="storage-quota">
      <div className="storage-quota-bar">
        <div className="storage-quota-fill" style={{ width: `${Math.min(percentage, 100)}%` }} />
      </div>
      <span className="storage-quota-text">
        {formatBytes(usedBytes)} / {formatBytes(limitBytes)}
      </span>
    </div>
  );
}
