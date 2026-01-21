type EmptyStateProps = {
  /** Optional callback when upload area is clicked */
  onUploadClick?: () => void;
};

/**
 * Empty state component shown when a folder has no contents.
 *
 * Displays a large drop zone with upload prompt.
 * Acts as both visual indicator and click target for uploads.
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolder } = useFolderNavigation();
 *
 *   if (currentFolder?.children.length === 0) {
 *     return <EmptyState onUploadClick={openUploadDialog} />;
 *   }
 *
 *   return <FileList items={currentFolder.children} />;
 * }
 * ```
 */
export function EmptyState({ onUploadClick }: EmptyStateProps) {
  return (
    <div
      className="empty-state"
      onClick={onUploadClick}
      role="button"
      tabIndex={onUploadClick ? 0 : undefined}
      onKeyDown={
        onUploadClick
          ? (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                onUploadClick();
              }
            }
          : undefined
      }
    >
      <div className="empty-state-content">
        <span className="empty-state-icon">📤</span>
        <p className="empty-state-text">Drag files here or click to upload</p>
        <p className="empty-state-hint">Your files are encrypted before leaving your device</p>
      </div>
    </div>
  );
}
