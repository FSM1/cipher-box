import { useState, useEffect, useCallback, useRef } from 'react';
import type { FilePointer } from '@cipherbox/crypto';
import { unwrapKey, hexToBytes, bytesToHex, clearBytes } from '@cipherbox/crypto';
import { registerStream, unregisterStream, isSwActive } from '../lib/sw-registration';
import { resolveFileMetadata } from '../services/file-metadata.service';
import { downloadFileFromIpns, triggerBrowserDownload } from '../services/download.service';
import { useAuthStore } from '../stores/auth.store';

type UseStreamingPreviewOptions = {
  open: boolean;
  item: FilePointer | null;
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
 * Resolves file metadata from IPNS, registers a decrypt stream context
 * with the Service Worker, and returns a /decrypt-stream/* URL that
 * <video> and <audio> elements can use as their src.
 *
 * Falls back gracefully when SW is not active or file uses GCM encryption.
 */
export function useStreamingPreview({
  open,
  item,
  mimeType,
  folderKey,
}: UseStreamingPreviewOptions): UseStreamingPreviewReturn {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [streamUrl, setStreamUrl] = useState<string | null>(null);
  const [decryptProgress, setDecryptProgress] = useState(0);
  const [swReady, setSwReady] = useState(false);
  const [isCtr, setIsCtr] = useState(false);

  // Track the current item's IPNS name for cleanup and message filtering
  const ipnsNameRef = useRef<string | null>(null);

  // Check SW readiness on mount/open
  useEffect(() => {
    if (open) {
      setSwReady(isSwActive());
    }
  }, [open]);

  // SW progress message listener
  useEffect(() => {
    if (!open || !swReady) return;

    const handleMessage = (event: MessageEvent) => {
      const data = event.data;
      if (!data || !data.type || !ipnsNameRef.current) return;

      // Only process messages for our stream
      if (data.fileMetaIpnsName !== ipnsNameRef.current) return;

      switch (data.type) {
        case 'fetch-progress': {
          const percent = data.total > 0 ? Math.min(100, (data.loaded / data.total) * 100) : 0;
          setDecryptProgress(percent);
          break;
        }
        case 'fetch-complete':
          setDecryptProgress(100);
          break;
        case 'fetch-error':
          setError(data.error || 'Failed to fetch encrypted content');
          break;
      }
    };

    navigator.serviceWorker.addEventListener('message', handleMessage);
    return () => {
      navigator.serviceWorker.removeEventListener('message', handleMessage);
    };
  }, [open, swReady]);

  // Main effect: resolve metadata and register stream
  useEffect(() => {
    if (!open || !item || !folderKey || !swReady) {
      return;
    }

    let cancelled = false;
    setLoading(true);
    setError(null);
    setDecryptProgress(0);
    setStreamUrl(null);
    setIsCtr(false);

    (async () => {
      try {
        // 1. Resolve file metadata from IPNS
        const { metadata: fileMeta } = await resolveFileMetadata(item.fileMetaIpnsName, folderKey);

        if (cancelled) return;

        // 2. Check encryption mode -- only CTR files use streaming
        if (!fileMeta.encryptionMode || fileMeta.encryptionMode === 'GCM') {
          setIsCtr(false);
          setLoading(false);
          return;
        }

        setIsCtr(true);

        // 3. Unwrap the file key
        const auth = useAuthStore.getState();
        if (!auth.vaultKeypair) {
          throw new Error('No keypair available - please log in again');
        }

        const fileKey = await unwrapKey(
          hexToBytes(fileMeta.fileKeyEncrypted),
          auth.vaultKeypair.privateKey
        );

        if (cancelled) return;

        // 4. Register stream with SW
        const fileKeyHex = bytesToHex(fileKey);
        clearBytes(fileKey);

        registerStream({
          fileMetaIpnsName: item.fileMetaIpnsName,
          fileKey: fileKeyHex,
          iv: fileMeta.fileIv,
          cid: fileMeta.cid,
          totalSize: fileMeta.size,
          mimeType,
        });

        ipnsNameRef.current = item.fileMetaIpnsName;

        // 5. Set stream URL for media element
        setStreamUrl('/decrypt-stream/' + item.fileMetaIpnsName);
        setLoading(false);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to set up streaming preview');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
      if (ipnsNameRef.current) {
        unregisterStream(ipnsNameRef.current);
        ipnsNameRef.current = null;
      }
    };
  }, [open, item, folderKey, swReady, mimeType]);

  // Cleanup on close
  useEffect(() => {
    if (!open && ipnsNameRef.current) {
      unregisterStream(ipnsNameRef.current);
      ipnsNameRef.current = null;
      setStreamUrl(null);
      setDecryptProgress(0);
      setError(null);
      setLoading(false);
      setIsCtr(false);
    }
  }, [open]);

  const cleanup = useCallback(() => {
    if (ipnsNameRef.current) {
      unregisterStream(ipnsNameRef.current);
      ipnsNameRef.current = null;
    }
    setStreamUrl(null);
    setDecryptProgress(0);
  }, []);

  const handleDownload = useCallback(() => {
    if (!item || !folderKey) return;

    const auth = useAuthStore.getState();
    if (!auth.vaultKeypair) return;

    downloadFileFromIpns({
      fileMetaIpnsName: item.fileMetaIpnsName,
      folderKey,
      privateKey: auth.vaultKeypair.privateKey,
      fileName: item.name,
    })
      .then((plaintext) => {
        triggerBrowserDownload(plaintext, item.name, mimeType);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Download failed');
      });
  }, [item, folderKey, mimeType]);

  return {
    loading,
    error,
    streamUrl,
    decryptProgress,
    isSwReady: swReady,
    isCtr,
    handleDownload,
    cleanup,
  };
}
