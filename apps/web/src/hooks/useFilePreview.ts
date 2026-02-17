import { useState, useEffect, useCallback } from 'react';
import type { FilePointer } from '@cipherbox/crypto';
import { useAuthStore } from '../stores/auth.store';
import { downloadFileFromIpns, triggerBrowserDownload } from '../services/download.service';

type UseFilePreviewOptions = {
  open: boolean;
  item: FilePointer | null;
  mimeType: string;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
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
 */
export function useFilePreview({
  open,
  item,
  mimeType,
  folderKey,
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

        const plaintext = await downloadFileFromIpns({
          fileMetaIpnsName: item.fileMetaIpnsName,
          folderKey: folderKey!,
          privateKey: auth.vaultKeypair.privateKey,
          fileName: item.name,
        });

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
  }, [open, item, folderKey, mimeType]);

  const handleDownload = useCallback(() => {
    if (!decryptedData || !item) return;
    triggerBrowserDownload(decryptedData, item.name, mimeType);
  }, [decryptedData, item, mimeType]);

  return { loading, error, objectUrl, decryptedData, handleDownload };
}
