import { useCallback } from 'react';
import { downloadAndSaveFile, FileMetadata } from '../services/download.service';
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

  const { derivedKeypair } = useAuthStore();

  const download = useCallback(
    async (metadata: FileMetadata): Promise<void> => {
      if (!derivedKeypair) {
        throw new Error('No keypair available - please log in again');
      }

      try {
        startDownload(metadata.originalName);

        // Download with progress tracking
        await downloadAndSaveFile(metadata, derivedKeypair.privateKey, (loaded, total) => {
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
    [derivedKeypair, startDownload, setProgress, setDecrypting, setSuccess, setError]
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
    reset,
  };
}
