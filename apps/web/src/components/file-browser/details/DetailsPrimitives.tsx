import { useState, useEffect, useCallback, useRef } from 'react';
import { copyTextToClipboard } from './copy-clipboard';

/**
 * Copyable value with a copy button.
 * Shows the full value with word-break and a small copy button.
 */
export function CopyableValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const handleCopy = useCallback(async () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    // D-14: only show "Copied!" when the copy actually succeeded.
    const success = await copyTextToClipboard(value);
    if (success) {
      setCopied(true);
      timeoutRef.current = setTimeout(() => setCopied(false), 2000);
    }
  }, [value]);

  return (
    <div className="details-copyable">
      <span className="details-copyable-text">{value}</span>
      <button
        type="button"
        className={`details-copy-btn ${copied ? 'details-copy-btn--copied' : ''}`}
        onClick={handleCopy}
        aria-label={copied ? 'Copied to clipboard' : 'Copy to clipboard'}
        aria-pressed={copied}
      >
        {copied ? 'ok' : 'cp'}
      </button>
    </div>
  );
}

/**
 * A single detail row with label and value.
 */
export function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="details-row">
      <span className="details-label">{label}</span>
      {children}
    </div>
  );
}

/**
 * Format a timestamp with time included for version entries.
 */
export function formatDateWithTime(timestamp: number): string {
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}
