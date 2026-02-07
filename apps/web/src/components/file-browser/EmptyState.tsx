/**
 * Terminal-style ASCII art for empty state using box-drawing characters.
 * Shows a mini terminal window with `ls -la` returning empty results.
 */
const terminalArt = `\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502 $ ls -la             \u2502
\u2502 total 0              \u2502
\u2502 $ \u2588                  \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

/**
 * Empty state component shown when a folder has no contents.
 *
 * Displays a terminal-window ASCII art with box-drawing characters
 * to indicate an empty directory. Upload functionality is provided
 * by the toolbar upload button, not embedded here.
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolder } = useFolderNavigation();
 *
 *   if (currentFolder?.children.length === 0) {
 *     return <EmptyState />;
 *   }
 *
 *   return <FileList items={currentFolder.children} />;
 * }
 * ```
 */
export function EmptyState() {
  return (
    <div className="empty-state" data-testid="empty-state">
      <div className="empty-state-content">
        <pre className="empty-state-ascii" aria-hidden="true">
          {terminalArt}
        </pre>
        <p className="empty-state-text">// EMPTY DIRECTORY</p>
        <p className="empty-state-hint">drag files here or use --upload</p>
      </div>
    </div>
  );
}
