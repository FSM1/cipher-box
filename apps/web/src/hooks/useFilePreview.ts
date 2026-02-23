import { useState, useEffect, useCallback } from 'react';
import type { FilePointer } from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import {
  downloadFile,
  downloadFileFromIpns,
  triggerBrowserDownload,
} from '../services/download.service';
import { resolveFileMetadata } from '../services/file-metadata.service';
import { fetchShareKeys } from '../services/share.service';

type UseFilePreviewOptions = {
  open: boolean;
  item: FilePointer | null;
  mimeType: string;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
  /** Share ID when previewing from a shared folder — uses re-wrapped file keys */
  shareId?: string | null;
};

type UseFilePreviewReturn = {
  loading: boolean;
  error: string | null;
  objectUrl: string | null;
  decryptedData: Uint8Array | null;
  handleDownload: () => void;
};

/**
 * Shared hook for file preview dialogs (v2 IPNS-based).
 *
 * Encapsulates the IPNS-resolve-download-decrypt-blob-URL lifecycle used by
 * PDF, audio, video, and image preview dialogs. Creates an object
 * URL from the decrypted file content and revokes it on close.
 *
 * When `shareId` is provided, fetches re-wrapped file keys from share_keys
 * instead of using the owner-encrypted key from file metadata.
 */
export function useFilePreview({
  open,
  item,
  mimeType,
  folderKey,
  shareId,
}: UseFilePreviewOptions): UseFilePreviewReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [decryptedData, setDecryptedData] = useState<Uint8Array | null>(null);

  useEffect(() => {
    if (!open || !item) {
      // Clean up object URL when closing
      if (objectUrl) {
        URL.revokeObjectURL(objectUrl);
      }
      setObjectUrl(null);
      setDecryptedData(null);
      setError(null);
      setLoading(false);
      return;
    }

    if (!folderKey) {
      setError('Folder key not available');
      return;
    }

    let cancelled = false;
    let url: string | null = null;
    setLoading(true);
    setError(null);

    (async () => {
      try {
        // Use getState() to avoid stale closures in async callbacks
        const auth = useAuthStore.getState();
        if (!auth.vaultKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        let plaintext: Uint8Array;

        if (shareId) {
          // Shared file path: use re-wrapped file key from share_keys
          const [{ metadata: fileMeta }, keys] = await Promise.all([
            resolveFileMetadata(item.fileMetaIpnsName, folderKey!),
            fetchShareKeys(shareId),
          ]);

          const fileKeyRecord = keys.find((k) => k.keyType === 'file' && k.itemId === item.id);
          if (!fileKeyRecord) {
            throw new Error('No re-wrapped file key available for this file');
          }

          plaintext = await downloadFile(
            {
              cid: fileMeta.cid,
              iv: fileMeta.fileIv,
              wrappedKey: fileKeyRecord.encryptedKey,
              originalName: item.name,
              encryptionMode: fileMeta.encryptionMode,
            },
            auth.vaultKeypair.privateKey
          );
        } else {
          // Owner path: use file key from metadata directly
          plaintext = await downloadFileFromIpns({
            fileMetaIpnsName: item.fileMetaIpnsName,
            folderKey: folderKey!,
            privateKey: auth.vaultKeypair.privateKey,
            fileName: item.name,
          });
        }

        if (cancelled) return;

        const blob = new Blob([plaintext as BlobPart], { type: mimeType });
        url = URL.createObjectURL(blob);

        setDecryptedData(plaintext);
        setObjectUrl(url);
        setLoading(false);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load file');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      if (url) {
        URL.revokeObjectURL(url);
      }
    };
  }, [open, item, folderKey, mimeType, shareId]);

  const handleDownload = useCallback(() => {
    if (!decryptedData || !item) return;
    triggerBrowserDownload(decryptedData, item.name, mimeType);
  }, [decryptedData, item, mimeType]);

  return { loading, error, objectUrl, decryptedData, handleDownload };
}
