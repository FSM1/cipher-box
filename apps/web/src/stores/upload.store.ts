import { create } from 'zustand';
import axios from 'axios';

type UploadStatus =
  | 'idle'
  | 'encrypting'
  | 'uploading'
  | 'registering'
  | 'success'
  | 'error'
  | 'cancelled';

type UploadState = {
  status: UploadStatus;
  progress: number; // 0-100 for current batch
  currentFile: string | null;
  totalFiles: number;
  completedFiles: number;
  error: string | null;
  cancelSource: ReturnType<typeof axios.CancelToken.source> | null;

  startUpload: (totalFiles: number) => void;
  setEncrypting: (filename: string) => void;
  setUploading: (filename: string, progress: number) => void;
  fileComplete: () => void;
  setRegistering: () => void;
  setSuccess: () => void;
  setError: (error: string) => void;
  cancel: () => void;
  reset: () => void;
};

export const useUploadStore = create<UploadState>((set, get) => ({
  status: 'idle',
  progress: 0,
  currentFile: null,
  totalFiles: 0,
  completedFiles: 0,
  error: null,
  cancelSource: null,

  startUpload: (totalFiles) =>
    set({
      status: 'encrypting',
      progress: 0,
      totalFiles,
      completedFiles: 0,
      error: null,
      cancelSource: axios.CancelToken.source(),
    }),

  setEncrypting: (filename) => set({ status: 'encrypting', currentFile: filename }),

  setUploading: (filename, progress) => {
    const { completedFiles, totalFiles } = get();
    const baseProgress = (completedFiles / totalFiles) * 100;
    const fileProgress = progress / totalFiles;
    set({
      status: 'uploading',
      currentFile: filename,
      progress: Math.round(baseProgress + fileProgress),
    });
  },

  fileComplete: () =>
    set((state) => ({
      completedFiles: state.completedFiles + 1,
      progress: Math.round(((state.completedFiles + 1) / state.totalFiles) * 100),
    })),

  setRegistering: () => set({ status: 'registering', currentFile: null }),
  setSuccess: () => set({ status: 'success', progress: 100, currentFile: null }),
  setError: (error) => set({ status: 'error', error, currentFile: null }),

  cancel: () => {
    const { cancelSource } = get();
    if (cancelSource) {
      cancelSource.cancel('Upload cancelled by user');
    }
    set({ status: 'cancelled', currentFile: null });
  },

  reset: () =>
    set({
      status: 'idle',
      progress: 0,
      currentFile: null,
      totalFiles: 0,
      completedFiles: 0,
      error: null,
      cancelSource: null,
    }),
}));
