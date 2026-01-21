import { UploadZone } from './UploadZone';

type EmptyStateProps = {
  /** Folder ID for upload destination */
  folderId: string;
};

/**
 * Empty state component shown when a folder has no contents.
 *
 * Displays a large drop zone with upload prompt using UploadZone.
 * Acts as both visual indicator and functional upload target.
 *
 * @example
 * ```tsx
 * function FileBrowser() {
 *   const { currentFolder, currentFolderId } = useFolderNavigation();
 *
 *   if (currentFolder?.children.length === 0) {
 *     return <EmptyState folderId={currentFolderId} />;
 *   }
 *
 *   return <FileList items={currentFolder.children} />;
 * }
 * ```
 */
export function EmptyState({ folderId }: EmptyStateProps) {
  return (
    <div className="empty-state">
      <div className="empty-state-content">
        <span className="empty-state-icon">📤</span>
        <p className="empty-state-text">This folder is empty</p>
        <p className="empty-state-hint">Your files are encrypted before leaving your device</p>
        <div className="empty-state-upload">
          <UploadZone folderId={folderId} />
        </div>
      </div>
    </div>
  );
}
