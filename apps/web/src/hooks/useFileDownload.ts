import { useCallback } from 'react';
import { triggerBrowserDownload } from '../services/download.service';
import { useDownloadStore } from '../stores/download.store';
import { getSdkClient, hasSdkClient } from '../lib/sdk-provider';
import { logger } from '../lib/logger';

export function useFileDownload() {
  const {
    status,
    progress,
    loadedBytes,
    totalBytes,
    currentFile,
    error,
    startDownload,
    setProgress,
    setDecrypting,
    setSuccess,
    setError,
    reset,
  } = useDownloadStore();

  /**
   * Download a file using per-file IPNS metadata (v2 flow) via SDK.
   *
   * The SDK resolves file IPNS, decrypts metadata with folderKey,
   * fetches + decrypts content. Browser download dialog triggered after.
   */
  const downloadFromIpns = useCallback(
    async (params: {
      fileMetaIpnsName: string;
      folderKey: Uint8Array;
      fileName: string;
    }): Promise<void> => {
      try {
        startDownload(params.fileName);

        if (!hasSdkClient()) {
          throw new Error('SDK not initialized — please log in again');
        }

        const client = getSdkClient();
        const decryptedBytes = await client.downloadFromIpns(
          params.fileMetaIpnsName,
          params.folderKey,
          (loaded, total) => setProgress(loaded, total)
        );

        setDecrypting();
        await new Promise((resolve) => setTimeout(resolve, 100));

        triggerBrowserDownload(decryptedBytes, params.fileName);
        setSuccess();
      } catch (err) {
        const message = (err as Error).message || 'Download failed';
        setError(message);
        logger.error('[Download] Download failed:', err);
        throw err;
      }
    },
    [startDownload, setProgress, setDecrypting, setSuccess, setError]
  );

  return {
    status,
    progress,
    loadedBytes,
    totalBytes,
    currentFile,
    error,
    isDownloading: status === 'downloading' || status === 'decrypting',
    downloadFromIpns,
    reset,
  };
}
