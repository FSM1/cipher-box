import { useState, useCallback } from 'react';
import type { FolderOperationState } from './folder-helpers';

/**
 * React hook for file version management operations (restore, delete).
 *
 * @stub phase 65 — version management requires Node read-chain (NodeContent.versions)
 * and write-chain (file IPNS private key inside sealed write-body).
 * The per-file IPNS key and file key are no longer in FilePointer (retired);
 * they live inside the Node's sealed bodies (NodeContent / NodeWriteBody).
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFileVersions() {
  const [state] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Restore a previous version of a file.
   * @stub phase 65 — requires NodeContent.versions + write-chain key
   */
  const handleRestoreVersion = useCallback(
    async (_parentId: string, _fileId: string, _versionIndex: number): Promise<void> => {
      throw new Error(
        'not implemented — phase 65 (version restore requires Node read-chain + write-chain)'
      );
    },
    []
  );

  /**
   * Delete a specific past version from a file's version history.
   * @stub phase 65 — requires NodeContent.versions + write-chain key
   */
  const handleDeleteVersion = useCallback(
    async (_parentId: string, _fileId: string, _versionIndex: number): Promise<void> => {
      throw new Error(
        'not implemented — phase 65 (version delete requires Node read-chain + write-chain)'
      );
    },
    []
  );

  return {
    ...state,
    restoreVersion: handleRestoreVersion,
    deleteVersion: handleDeleteVersion,
  };
}
