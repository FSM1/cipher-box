/** Terminal window running `ls -la` over nothing, in box-drawing characters. */
const TERMINAL_ART = `┌──────────────────────┐
│ $ ls -la             │
│ total 0              │
│ $ █                  │
└──────────────────────┘`;

/** What a folder with no children shows. */
export function EmptyState() {
  return (
    <div className="empty-state" data-testid="empty-state">
      <div className="empty-state-content">
        <pre className="empty-state-ascii" aria-hidden="true">
          {TERMINAL_ART}
        </pre>
        <p className="empty-state-text">// EMPTY DIRECTORY</p>
      </div>
    </div>
  );
}
