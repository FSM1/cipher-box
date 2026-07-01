import { useState, useCallback } from 'react';
import type { FolderOperationState } from './folder-helpers';
import { runWithFailureUx } from './useMutationFailureUx';

/**
 * React hook for file add/update operations.
 *
 * @stub phase 65 — file update requires Node read-chain (to resolve current
 * NodeContent) and write-chain (file IPNS private key inside sealed write-body).
 * The per-file IPNS key and file key are no longer in FilePointer (retired);
 * they live inside the Node's sealed bodies (NodeContent / NodeWriteBody).
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFileOperations() {
  const [state] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Update a file's content in-place.
   * @stub phase 65 — requires NodeContent + write-chain key. The eventual
   * SDK mutation call belongs inside runWithFailureUx (68-09) alongside
   * every other client.X() invocation in this hook set.
   */
  const handleUpdateFile = useCallback(
    async (
      _parentId: string,
      _fileData: {
        fileId: string;
        newCid: string;
        newFileKeyEncrypted: string;
        newFileIv: string;
        newSize: number;
        newEncryptionMode?: 'GCM' | 'CTR';
        forceVersion?: boolean;
      }
    ): Promise<void> => {
      await runWithFailureUx(async () => {
        throw new Error(
          'not implemented — phase 65 (file update requires Node read-chain + write-chain)'
        );
      });
    },
    []
  );

  return {
    ...state,
    updateFile: handleUpdateFile,
  };
}
