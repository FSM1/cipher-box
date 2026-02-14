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
