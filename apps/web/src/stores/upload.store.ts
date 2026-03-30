import { create } from 'zustand';
import axios from 'axios';

export type PendingReplacement = {
  fileName: string;
  fileId: string;
  parentId: string;
  encryptedData: {
    cid: string;
    wrappedKey: string;
    iv: string;
    size: number;
    encryptionMode: 'GCM' | 'CTR';
  };
};

export type PerFileUpload = {
  id: string; // format: `upload-${filename}-${Date.now()}`
  filename: string;
  targetFolderId: string; // folder ID where this file is being uploaded
  status: 'encrypting' | 'uploading' | 'complete' | 'error' | 'cancelled';
  progress: number; // 0-100
  error: string | null;
  cancelSource: ReturnType<typeof axios.CancelToken.source> | null;
  file: File | null; // Original File reference for retry (D-09)
};

type UploadState = {
  files: Map<string, PerFileUpload>;
  pendingReplacements: PendingReplacement[];

  // Per-file actions
  addFile: (id: string, filename: string, targetFolderId: string, file: File) => void;
  updateFileProgress: (id: string, progress: number) => void;
  setFileStatus: (id: string, status: PerFileUpload['status'], error?: string) => void;
  setFileComplete: (id: string) => void;
  removeFile: (id: string) => void;
  cancelFile: (id: string) => void;
  retryFile: (id: string) => void;

  // Batch-level actions (kept for backward compat / derived)
  reset: () => void;

  // PendingReplacements (unchanged)
  setPendingReplacements: (replacements: PendingReplacement[]) => void;
  clearPendingReplacements: () => void;
};

export const useUploadStore = create<UploadState>((set, get) => ({
  files: new Map<string, PerFileUpload>(),
  pendingReplacements: [],

  addFile: (id, filename, targetFolderId, file) =>
    set((state) => {
      const next = new Map(state.files);
      next.set(id, {
        id,
        filename,
        targetFolderId,
        status: 'encrypting',
        progress: 0,
        error: null,
        cancelSource: axios.CancelToken.source(),
        file,
      });
      return { files: next };
    }),

  updateFileProgress: (id, progress) =>
    set((state) => {
      const entry = state.files.get(id);
      if (!entry) return state;
      const next = new Map(state.files);
      next.set(id, { ...entry, status: 'uploading', progress });
      return { files: next };
    }),

  setFileStatus: (id, status, error) =>
    set((state) => {
      const entry = state.files.get(id);
      if (!entry) return state;
      const next = new Map(state.files);
      const updates: Partial<PerFileUpload> = { status, error: error ?? null };
      if (status === 'complete') {
        updates.progress = 100;
      }
      next.set(id, { ...entry, ...updates });
      return { files: next };
    }),

  setFileComplete: (id) =>
    set((state) => {
      const entry = state.files.get(id);
      if (!entry) return state;
      const next = new Map(state.files);
      next.set(id, { ...entry, status: 'complete', progress: 100 });
      return { files: next };
    }),

  removeFile: (id) =>
    set((state) => {
      const next = new Map(state.files);
      next.delete(id);
      return { files: next };
    }),

  cancelFile: (id) =>
    set((state) => {
      const entry = state.files.get(id);
      if (!entry) return state;
      entry.cancelSource?.cancel('Upload cancelled by user');
      const next = new Map(state.files);
      next.set(id, { ...entry, status: 'cancelled' });
      return { files: next };
    }),

  retryFile: (id) =>
    set((state) => {
      const entry = state.files.get(id);
      if (!entry) return state;
      const next = new Map(state.files);
      next.set(id, {
        ...entry,
        status: 'encrypting',
        progress: 0,
        error: null,
        cancelSource: axios.CancelToken.source(),
      });
      return { files: next };
    }),

  reset: () => {
    // Cancel all active uploads before clearing
    const { files } = get();
    for (const entry of files.values()) {
      if (entry.cancelSource && (entry.status === 'encrypting' || entry.status === 'uploading')) {
        entry.cancelSource.cancel('Upload cancelled by user');
      }
    }
    set({
      files: new Map<string, PerFileUpload>(),
      pendingReplacements: [],
    });
  },

  setPendingReplacements: (replacements) => set({ pendingReplacements: replacements }),
  clearPendingReplacements: () => set({ pendingReplacements: [] }),
}));
