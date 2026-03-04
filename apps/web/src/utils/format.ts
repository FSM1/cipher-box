/**
 * Format utilities for file browser display.
 */

/**
 * Format bytes into human-readable string.
 *
 * @param bytes - Number of bytes
 * @returns Formatted string like "1.2 MB", "456 KB", etc.
 *
 * @example
 * formatBytes(1024) // "1 KB"
 * formatBytes(1536) // "1.5 KB"
 * formatBytes(1048576) // "1 MB"
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';

  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const k = 1024;
  const i = Math.floor(Math.log(bytes) / Math.log(k));

  // Use at most 1 decimal place, remove trailing zeros
  const value = bytes / Math.pow(k, i);
  const formatted = value % 1 === 0 ? value.toString() : value.toFixed(1);

  return `${formatted} ${units[i]}`;
}

/**
 * Format timestamp into locale-aware date string.
 *
 * @param timestamp - Unix timestamp in milliseconds
 * @returns Formatted date string
 *
 * @example
 * formatDate(1705852800000) // "Jan 21, 2024" (varies by locale)
 */
export function formatDate(timestamp: number): string {
  const date = new Date(timestamp);

  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(date);
}

/**
 * Format a Unix ms timestamp as a relative time string.
 *
 * Returns "just now", "Xm ago", "Xh ago", "Xd ago" for recent timestamps.
 * Falls back to a locale-formatted date for timestamps older than 7 days.
 */
export function formatRelativeTime(timestampMs: number): string {
  const diff = Date.now() - timestampMs;

  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  if (diff < 604_800_000) {
    const days = Math.floor(diff / 86_400_000);
    return days === 1 ? '1 day ago' : `${days} days ago`;
  }

  return new Date(timestampMs).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
  });
}

/**
 * Get a terminal-style type indicator based on item type and optional MIME type.
 */
export function getItemIcon(itemType: 'file' | 'folder', mimeType?: string): string {
  if (itemType === 'folder') return '[DIR]';
  if (!mimeType) return '[FILE]';
  if (mimeType.startsWith('image/')) return '[IMG]';
  if (mimeType.startsWith('video/')) return '[VID]';
  if (mimeType.startsWith('audio/')) return '[AUD]';
  if (mimeType.startsWith('text/')) return '[TXT]';
  if (mimeType === 'application/pdf') return '[PDF]';
  return '[FILE]';
}
