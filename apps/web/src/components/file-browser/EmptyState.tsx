import { UploadZone } from './UploadZone';

type EmptyStateProps = {
  /** Folder ID for upload destination */
  folderId: string;
};

/**
 * Terminal-style ASCII art folder icon for empty state.
 */
const asciiArt = `
   ___________
  /          /|
 /          / |
|__________|  |
|          |  /
|__________|/
`;

/**
 * Empty state component shown when a folder has no contents.
 *
 * Displays terminal-style ASCII art with drop zone for uploads.
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
    <div className="empty-state" data-testid="empty-state">
      <div className="empty-state-content">
        <pre className="empty-state-ascii" aria-hidden="true">
          {asciiArt}
        </pre>
        <p className="empty-state-text">// EMPTY DIRECTORY</p>
        <p className="empty-state-hint">drag files here or use upload</p>
        <div className="empty-state-upload">
          <UploadZone folderId={folderId} />
        </div>
      </div>
    </div>
  );
}
