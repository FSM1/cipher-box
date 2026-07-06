import { useState, useEffect, useCallback, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { bytesToHex, clearBytes } from '@cipherbox/crypto';
import { downloadFileFromIpns, triggerBrowserDownload } from '../services/download.service';
import { registerStream, unregisterStream, isSwActive, waitForSW } from '../lib/sw-registration';
import { getSdkClient } from '../lib/sdk-provider';

type UseStreamingPreviewOptions = {
  open: boolean;
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

/** Decodes a base64 string to a Uint8Array (NodeContent.fileIv is base64, v3 contract). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/** SW -> main-thread progress/error messages posted from decrypt-sw.ts. */
type SwMessage =
  | { type: 'fetch-progress'; fileMetaIpnsName: string; loaded: number; total: number }
  | { type: 'fetch-complete'; fileMetaIpnsName: string }
  | { type: 'fetch-error'; fileMetaIpnsName: string; error: string }
  | { type: 'token-expired' };

/**
 * Hook for SW-based streaming media preview of CTR-encrypted files.
 *
 * Resolves the file's `NodeContent` via `client.resolveFileMetadata`; when
 * `encryptionMode === 'CTR'` it registers a decrypt context with the Service
 * Worker (raw fileKey + base64 iv converted to hex, matching decrypt-sw.ts's
 * contract) and exposes `/decrypt-stream/{ipnsName}` as the media element src.
 * Non-CTR files resolve with `isCtr: false` so callers fall back to the GCM
 * blob-URL path (`useFilePreview`).
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
  const [isSwReady, setIsSwReady] = useState(false);
  const [isCtr, setIsCtr] = useState(false);
  const registeredIpnsNameRef = useRef<string | null>(null);

  const teardown = useCallback(() => {
    if (registeredIpnsNameRef.current) {
      unregisterStream(registeredIpnsNameRef.current);
      registeredIpnsNameRef.current = null;
    }
  }, []);

  const cleanup = useCallback(() => {
    teardown();
    setStreamUrl(null);
    setDecryptProgress(0);
    setIsSwReady(false);
    setIsCtr(false);
  }, [teardown]);

  // Listen for SW fetch-progress/fetch-complete/fetch-error messages, scoped to
  // the currently-registered stream.
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;

    const handleMessage = (event: MessageEvent) => {
      const data = event.data as SwMessage;
      if (data.type === 'token-expired') return;
      if (data.fileMetaIpnsName !== registeredIpnsNameRef.current) return;

      if (data.type === 'fetch-progress') {
        setDecryptProgress(data.total > 0 ? Math.min(100, (data.loaded / data.total) * 100) : 0);
      } else if (data.type === 'fetch-complete') {
        setDecryptProgress(100);
      } else if (data.type === 'fetch-error') {
        setError(data.error);
      }
    };

    navigator.serviceWorker.addEventListener('message', handleMessage);
    return () => {
      navigator.serviceWorker.removeEventListener('message', handleMessage);
    };
  }, []);

  useEffect(() => {
    // Always clear any previous registration before evaluating the new state --
    // switching items while the dialog stays open must not leak the old stream.
    teardown();
    setStreamUrl(null);
    setDecryptProgress(0);
    setIsSwReady(false);
    setIsCtr(false);

    if (!open || !item) {
      setError(null);
      setLoading(false);
      return;
    }

    if (!('serviceWorker' in navigator)) {
      setError('Service Worker not supported — streaming preview unavailable');
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

    (async () => {
      try {
        const { metadata } = await getSdkClient().resolveFileMetadata(item, folderKey);
        if (cancelled) return;

        if (metadata.encryptionMode !== 'CTR') {
          // This hook is the terminal consumer of resolveFileMetadata's freshly
          // unsealed fileKey (D-09); the CTR path below zeroes it, so the non-CTR
          // early return must zero it too rather than leak it in memory.
          clearBytes(metadata.fileKey);
          setIsCtr(false);
          setLoading(false);
          return;
        }
        setIsCtr(true);

        await waitForSW();
        if (cancelled) return;

        if (!isSwActive()) {
          setError('Service Worker not active — streaming preview unavailable');
          setLoading(false);
          return;
        }

        // `metadata.fileKey` is freshly unsealed by resolveFileMetadata; this hook
        // is its terminal consumer (D-09) -- convert to hex for the SW contract and
        // zero the raw bytes immediately, before registering the stream.
        const fileKeyHex = bytesToHex(metadata.fileKey);
        clearBytes(metadata.fileKey);
        const ivHex = bytesToHex(base64ToBytes(metadata.fileIv));

        registerStream({
          fileMetaIpnsName: item.ipnsName,
          fileKey: fileKeyHex,
          iv: ivHex,
          cid: metadata.cid,
          totalSize: metadata.size,
          mimeType,
        });
        registeredIpnsNameRef.current = item.ipnsName;

        if (cancelled) {
          teardown();
          return;
        }

        setStreamUrl(`/decrypt-stream/${item.ipnsName}`);
        setIsSwReady(true);
        setLoading(false);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : 'Failed to load streaming preview');
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [open, item, folderKey, mimeType, teardown]);

  // Unregister on unmount.
  useEffect(() => {
    return () => {
      teardown();
    };
  }, [teardown]);

  const handleDownload = useCallback(() => {
    if (!item || !folderKey) return;
    downloadFileFromIpns({ fileRef: item, folderKey })
      .then((plaintext) => {
        triggerBrowserDownload(plaintext, item.name, mimeType);
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to download file');
      });
  }, [item, folderKey, mimeType]);

  return {
    loading,
    error,
    streamUrl,
    decryptProgress,
    isSwReady,
    isCtr,
    handleDownload,
    cleanup,
  };
}
