import { useState, useEffect, useCallback, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { downloadFileFromIpns, triggerBrowserDownload } from '../services/download.service';

type UseFilePreviewOptions = {
  open: boolean;
  item: SealedChildRef | null;
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
 * Shared hook for file preview dialogs.
 *
 * Resolves the owned file's `NodeContent` (`resolveFileMetadata`) and downloads +
 * decrypts its content (`downloadFileFromIpns`, raw fileKey, GCM/CTR per
 * `encryptionMode`) to build a Blob object URL for the preview surface.
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
  const objectUrlRef = useRef<string | null>(null);

  useEffect(() => {
    if (!open || !item) {
      if (objectUrlRef.current) {
        URL.revokeObjectURL(objectUrlRef.current);
        objectUrlRef.current = null;
      }
      setObjectUrl(null);
      setDecryptedData(null);
      setError(null);
      setLoading(false);
      return;
    }

    if (!folderKey) {
      setLoading(false);
      setError('Folder key not available');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);

    downloadFileFromIpns({ fileRef: item, folderKey })
      .then((plaintext) => {
        if (cancelled) return;
        // Pass the typed array directly -- never `.buffer` (may include padding bytes
        // from the underlying ArrayBuffer, silently corrupting the preview).
        const blob = new Blob([plaintext as BlobPart], { type: mimeType });
        const url = URL.createObjectURL(blob);
        if (objectUrlRef.current) {
          URL.revokeObjectURL(objectUrlRef.current);
        }
        objectUrlRef.current = url;
        setObjectUrl(url);
        setDecryptedData(plaintext);
        setLoading(false);
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load file preview');
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [open, item, folderKey, mimeType]);

  // Revoke the object URL on unmount (dialog close is handled by the effect above).
  useEffect(() => {
    return () => {
      if (objectUrlRef.current) {
        URL.revokeObjectURL(objectUrlRef.current);
        objectUrlRef.current = null;
      }
    };
  }, []);

  const handleDownload = useCallback(() => {
    if (!decryptedData || !item) return;
    triggerBrowserDownload(decryptedData, item.name, mimeType);
  }, [decryptedData, item, mimeType]);

  return { loading, error, objectUrl, decryptedData, handleDownload };
}
