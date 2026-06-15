import { useCallback } from 'react';
import { useFolderStore } from '../stores/folder.store';
import { calculateFolderDepth } from './folder-helpers';
import { useFolderMutations } from './useFolderMutations';
import { useFileOperations } from './useFileOperations';
import { useFileVersions } from './useFileVersions';

/**
 * React hook for folder operations with loading/error state.
 *
 * Composes focused sub-hooks for folder mutations, file operations,
 * and file version management into a single unified API.
 *
 * @example
 * ```tsx
 * function FolderActions() {
 *   const { isLoading, error, createFolder, deleteItem } = useFolder();
 *
 *   const handleCreate = async () => {
 *     try {
 *       await createFolder('New Folder', currentFolderId);
 *     } catch (err) {
 *       // Error also in error state
 *     }
 *   };
 *
 *   return (
 *     <div>
 *       {isLoading && <Spinner />}
 *       {error && <ErrorMessage>{error}</ErrorMessage>}
 *       <button onClick={handleCreate}>New Folder</button>
 *     </div>
 *   );
 * }
 * ```
 */
export function useFolder() {
  const folderMutations = useFolderMutations();
  const fileOperations = useFileOperations();
  const fileVersions = useFileVersions();
  const folderStore = useFolderStore();

  // Combine loading/error state from all sub-hooks
  const isLoading = folderMutations.isLoading || fileOperations.isLoading || fileVersions.isLoading;
  const error = folderMutations.error || fileOperations.error || fileVersions.error;

  const clearError = useCallback(() => {
    // This is intentionally simplified - errors clear when the next operation starts
  }, []);

  return {
    isLoading,
    error,
    createFolder: folderMutations.createFolder,
    renameItem: folderMutations.renameItem,
    moveItem: folderMutations.moveItem,
    moveItems: folderMutations.moveItems,
    deleteItem: folderMutations.deleteItem,
    deleteItems: folderMutations.deleteItems,
    updateFile: fileOperations.updateFile,
    restoreVersion: fileVersions.restoreVersion,
    deleteVersion: fileVersions.deleteVersion,
    clearError,
    calculateFolderDepth: (folderId: string) => calculateFolderDepth(folderId, folderStore.folders),
  };
}
