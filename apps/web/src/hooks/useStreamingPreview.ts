import { useState, useCallback } from 'react';
import type { SealedChildRef } from '@cipherbox/core';

type UseStreamingPreviewOptions = {
  open: boolean;
  /** @stub phase 63 — streaming preview requires Node read-chain */
  item: SealedChildRef | null;
  mimeType: string;
  /** Parent folder's decrypted AES-256 key (needed to decrypt file metadata) */
  folderKey: Uint8Array | null;
};

type UseStreamingPreviewReturn = {
  /** True during initial metadata resolution */
  loading: boolean;
  error: string | null;
  /** /decrypt-stream/{ipnsName} URL for media element src */
  streamUrl: string | null;
  /** 0-100, tracks SW encrypted file fetch progress */
  decryptProgress: number;
  /** Whether SW is active and can handle requests */
  isSwReady: boolean;
  /** Whether the file uses CTR encryption (streaming-eligible) */
  isCtr: boolean;
  /** Download the full decrypted file */
  handleDownload: () => void;
  /** Unregister stream on close */
  cleanup: () => void;
};

/**
 * Hook for SW-based streaming media preview of CTR-encrypted files.
 *
 * @stub phase 63 — streaming preview requires Node read-chain navigation.
 * The file CID, fileKey, and encryptionMode are now inside NodeContent
 * (sealed under the file node's readKey). Phase 63 will unseal the Node
 * to recover NodeContent and wire streaming.
 */
export function useStreamingPreview({
  open: _open,
  item: _item,
  mimeType: _mimeType,
  folderKey: _folderKey,
}: UseStreamingPreviewOptions): UseStreamingPreviewReturn {
  const [error] = useState<string | null>(
    'not implemented — phase 63 (streaming preview requires Node read-chain)'
  );

  const handleDownload = useCallback(() => {
    throw new Error('not implemented — phase 63 (streaming download requires Node read-chain)');
  }, []);

  const cleanup = useCallback(() => {
    // no-op: nothing registered yet
  }, []);

  return {
    loading: false,
    error,
    streamUrl: null,
    decryptProgress: 0,
    isSwReady: false,
    isCtr: false,
    handleDownload,
    cleanup,
  };
}
