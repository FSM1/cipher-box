/** Display formatting for the vault browser. */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'] as const;

/** Human-readable byte count, at most one decimal place. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';

  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1);
  const value = bytes / 1024 ** exponent;
  const rounded = value % 1 === 0 ? value.toString() : value.toFixed(1);

  return `${rounded} ${UNITS[exponent]}`;
}

/** Locale-aware date for a Unix-millisecond timestamp. */
export function formatDate(timestampMillis: number): string {
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  }).format(new Date(timestampMillis));
}
