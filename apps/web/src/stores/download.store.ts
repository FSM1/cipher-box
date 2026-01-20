import { create } from 'zustand';

type DownloadStatus = 'idle' | 'downloading' | 'decrypting' | 'success' | 'error';

type DownloadState = {
  status: DownloadStatus;
  progress: number; // 0-100
  loadedBytes: number;
  totalBytes: number;
  currentFile: string | null;
  error: string | null;

  startDownload: (filename: string) => void;
  setProgress: (loaded: number, total: number) => void;
  setDecrypting: () => void;
  setSuccess: () => void;
  setError: (error: string) => void;
  reset: () => void;
};

export const useDownloadStore = create<DownloadState>((set) => ({
  status: 'idle',
  progress: 0,
  loadedBytes: 0,
  totalBytes: 0,
  currentFile: null,
  error: null,

  startDownload: (filename) =>
    set({
      status: 'downloading',
      progress: 0,
      loadedBytes: 0,
      totalBytes: 0,
      currentFile: filename,
      error: null,
    }),

  setProgress: (loaded, total) => {
    const progress = total > 0 ? Math.round((loaded * 100) / total) : 0;
    set({ loadedBytes: loaded, totalBytes: total, progress });
  },

  setDecrypting: () => set({ status: 'decrypting' }),

  setSuccess: () =>
    set({
      status: 'success',
      progress: 100,
      currentFile: null,
    }),

  setError: (error) =>
    set({
      status: 'error',
      error,
      currentFile: null,
    }),

  reset: () =>
    set({
      status: 'idle',
      progress: 0,
      loadedBytes: 0,
      totalBytes: 0,
      currentFile: null,
      error: null,
    }),
}));
