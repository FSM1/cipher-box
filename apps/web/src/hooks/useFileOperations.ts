import { useState, useCallback } from 'react';
import { unwrapKey, hexToBytes } from '@cipherbox/crypto';
import type { FolderOperationState } from './folder-helpers';
import { getRootFolderState } from './folder-helpers';
import { useAuthStore } from '../stores/auth.store';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { getSdkClient } from '../lib/sdk-provider';
import { shouldCreateVersion } from '../lib/version-transforms';
import { runWithFailureUx } from './useMutationFailureUx';
import { logger } from '../lib/logger';

/**
 * React hook for file add/update operations.
 *
 * `handleUpdateFile` (68.1-12) resolves the file's write-chain signing key via
 * `client.resolveFileIpnsPrivateKey` (T-68.1-12-04) and the current `NodeContent`
 * via the read-chain (`client.resolveFileMetadata`, 68.2-11 SDK facade), unwraps the caller-supplied
 * ECIES-wrapped content key (`ReplaceFileDialog`'s upload pipeline still produces
 * a wrapped hex key — out of this plan's scope to change), and publishes via
 * `client.replaceFile` (68.1-09) inside `runWithFailureUx`.
 *
 * Returns loading/error state and operation callbacks.
 */
export function useFileOperations() {
  const [state, setState] = useState<FolderOperationState>({
    isLoading: false,
    error: null,
  });

  /**
   * Update a file's content in-place.
   *
   * @param parentId - Parent folder ID ('root' or folder UUID)
   * @param fileData.fileId - IPNS name of the file (`SealedChildRef.ipnsName`)
   * @param fileData.newFileKeyEncrypted - Hex-encoded ECIES-wrapped new content key
   *   (wrapped under the user's own public key by the upload pipeline) — unwrapped
   *   here with the user's private key to recover the raw fileKey the v3 model needs.
   */
  const handleUpdateFile = useCallback(
    async (
      parentId: string,
      fileData: {
        fileId: string;
        newCid: string;
        newFileKeyEncrypted: string;
        newFileIv: string;
        newSize: number;
        newEncryptionMode?: 'GCM' | 'CTR';
        forceVersion?: boolean;
      }
    ): Promise<void> => {
      setState({ isLoading: true, error: null });
      try {
        const auth = useAuthStore.getState();
        if (!auth.vaultKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        const folders = useFolderStore.getState().folders;
        const parentFolder =
          parentId === 'root'
            ? getRootFolderState(useVaultStore.getState(), folders)
            : folders[parentId];
        if (!parentFolder) {
          throw new Error('Parent folder not found or vault not initialized');
        }

        // Raw identity (readKeySealed/generation/versionFloor) is needed to
        // unseal the file's read-chain -- the store's display `children`
        // (ResolvedChild[], Plan 09) no longer carries these; `rawChildren`
        // is the same-session write-path mirror (D-09).
        const fileRef = (parentFolder.rawChildren ?? []).find(
          (c) => c.ipnsName === fileData.fileId
        );
        if (!fileRef) {
          throw new Error('File not found in folder');
        }

        const client = getSdkClient();
        const { metadata: currentMetadata } = await client.resolveFileMetadata(
          fileRef,
          parentFolder.folderKey
        );

        const createVersion = shouldCreateVersion(
          currentMetadata.versions,
          fileData.forceVersion ?? false
        );

        let newFileKey: Uint8Array | null = await unwrapKey(
          hexToBytes(fileData.newFileKeyEncrypted),
          auth.vaultKeypair.privateKey
        );

        let prunedCids: string[] = [];
        // Open the guarded try immediately after unwrapping newFileKey so its
        // finally always zeroes the raw key — even if resolveFileIpnsPrivateKey
        // throws before replaceFile runs (D-09).
        try {
          // T-68.1-12-04: the write-chain walk lives only inside CipherBoxClient
          // (D-03) — this is the only way to pre-resolve the file's own IPNS
          // signing key from the web layer. Do NOT zero it here — sdk-core
          // updateFileMetadata is its terminal owner (T-47-01).
          const fileIpnsPrivateKey = await client.resolveFileIpnsPrivateKey(
            parentFolder.ipnsName,
            fileData.fileId
          );

          ({ prunedCids } = await runWithFailureUx(() =>
            client.replaceFile(parentFolder.ipnsName, fileData.fileId, {
              fileIpnsPrivateKey,
              currentMetadata,
              updates: {
                cid: fileData.newCid,
                fileKey: newFileKey!,
                fileIv: hexToBytes(fileData.newFileIv),
                size: fileData.newSize,
                mimeType: currentMetadata.mimeType,
                encryptionMode: fileData.newEncryptionMode ?? currentMetadata.encryptionMode,
              },
              createVersion,
            })
          ));
        } finally {
          newFileKey?.fill(0);
          newFileKey = null;
        }

        for (const cid of prunedCids) {
          client.unpin(cid).catch((err) => logger.warn('[FileOps] Unpin pruned CID failed:', err));
        }

        setState({ isLoading: false, error: null });
      } catch (err) {
        const error = err instanceof Error ? err.message : 'Failed to update file';
        setState({ isLoading: false, error });
        throw err;
      }
    },
    []
  );

  return {
    ...state,
    updateFile: handleUpdateFile,
  };
}
