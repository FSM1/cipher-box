import { useState, useEffect, useCallback } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { triggerBrowserDownload } from '../services/download.service';

type UseFilePreviewOptions = {
  open: boolean;
  /** @stub phase 63 — file content resolution requires Node read-chain */
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
 * @stub phase 63 — file content resolution requires Node read-chain navigation.
 * The per-file IPNS name and file key are now inside the Node's sealed read-body
 * (NodeContent), not exposed on the SealedChildRef. Phase 63 will unseal the Node
 * to recover NodeContent and wire preview.
 */
export function useFilePreview({
  open,
  item,
  mimeType,
  folderKey: _folderKey,
  shareId: _shareId,
}: UseFilePreviewOptions): UseFilePreviewReturn {
  const [loading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [decryptedData, setDecryptedData] = useState<Uint8Array | null>(null);

  useEffect(() => {
    if (!open || !item) {
      if (objectUrl) URL.revokeObjectURL(objectUrl);
      setObjectUrl(null);
      setDecryptedData(null);
      setError(null);
      return;
    }
    // TODO(phase 63): unseal Node read-body to get NodeContent, then fetch/decrypt
    setError('not implemented — phase 63 (file preview requires Node read-chain)');
  }, [open, item, mimeType]);

  const handleDownload = useCallback(() => {
    if (!decryptedData || !item) return;
    triggerBrowserDownload(decryptedData, item.name, mimeType);
  }, [decryptedData, item, mimeType]);

  return { loading, error, objectUrl, decryptedData, handleDownload };
}
