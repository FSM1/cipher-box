import { useCallback } from 'react';
import {
  downloadAndSaveFile,
  downloadFileFromIpns,
  triggerBrowserDownload,
  FileMetadata,
} from '../services/download.service';
import { useDownloadStore } from '../stores/download.store';
import { useAuthStore } from '../stores/auth.store';

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

  const { vaultKeypair } = useAuthStore();

  const download = useCallback(
    async (metadata: FileMetadata): Promise<void> => {
      if (!vaultKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      try {
        startDownload(metadata.originalName);

        // Download with progress tracking
        await downloadAndSaveFile(metadata, vaultKeypair.privateKey, (loaded, total) => {
          setProgress(loaded, total);
        });

        setDecrypting();

        // Small delay for UX - show decrypting state
        await new Promise((resolve) => setTimeout(resolve, 100));

        setSuccess();
      } catch (err) {
        const message = (err as Error).message || 'Download failed';
        setError(message);
        console.error('Download failed:', err);
        throw err;
      }
    },
    [vaultKeypair, startDownload, setProgress, setDecrypting, setSuccess, setError]
  );

  /**
   * Download a file using per-file IPNS metadata (v2 flow).
   *
   * Resolves file IPNS, decrypts metadata with folderKey, fetches+decrypts content,
   * and triggers browser download dialog.
   */
  const downloadFromIpns = useCallback(
    async (params: {
      fileMetaIpnsName: string;
      folderKey: Uint8Array;
      fileName: string;
    }): Promise<void> => {
      const auth = useAuthStore.getState();
      if (!auth.vaultKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      try {
        startDownload(params.fileName);

        const plaintext = await downloadFileFromIpns({
          fileMetaIpnsName: params.fileMetaIpnsName,
          folderKey: params.folderKey,
          privateKey: auth.vaultKeypair.privateKey,
          fileName: params.fileName,
        });

        setDecrypting();
        await new Promise((resolve) => setTimeout(resolve, 100));

        triggerBrowserDownload(plaintext, params.fileName);
        setSuccess();
      } catch (err) {
        const message = (err as Error).message || 'Download failed';
        setError(message);
        console.error('Download failed:', err);
        throw err;
      }
    },
    [startDownload, setDecrypting, setSuccess, setError]
  );

  return {
    // State
    status,
    progress,
    loadedBytes,
    totalBytes,
    currentFile,
    error,
    isDownloading: status === 'downloading' || status === 'decrypting',

    // Actions
    download,
    downloadFromIpns,
    reset,
  };
}
