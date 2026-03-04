/**
 * Terminal-style ASCII art for bin empty state.
 */
const binEmptyArt = `\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502 $ ls ~/bin           \u2502
\u2502 total 0              \u2502
\u2502 $ \u2588                  \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

type BinEmptyStateProps = {
  /** Retention period in days for display */
  retentionDays: number;
};

/**
 * Empty state shown when the recycle bin has no items.
 * Follows the same terminal aesthetic as EmptyState.tsx.
 */
export function BinEmptyState({ retentionDays }: BinEmptyStateProps) {
  return (
    <div className="empty-state bin-empty-state" data-testid="bin-empty-state">
      <div className="empty-state-content">
        <pre className="empty-state-ascii" aria-hidden="true">
          {binEmptyArt}
        </pre>
        <p className="empty-state-text">{'// BIN IS EMPTY'}</p>
        <p className="empty-state-hint">deleted items will appear here for {retentionDays} days</p>
      </div>
    </div>
  );
}
