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
  id: string;
  filename: string;
  targetFolderId: string;
  status: 'encrypting' | 'uploading' | 'complete' | 'error';
  progress: number; // 0-100
  error: string | null;
  cancelSource: ReturnType<typeof axios.CancelToken.source> | null;
  file: File | null; // Original File reference for retry (D-09)
};

export function createUploadId(filename: string): string {
  return `upload-${filename}-${Date.now()}`;
}

export function isActiveUpload(status: PerFileUpload['status']): boolean {
  return status === 'encrypting' || status === 'uploading';
}

type UploadState = {
  files: Map<string, PerFileUpload>;
  pendingReplacements: PendingReplacement[];

  // Per-file actions
  addFile: (id: string, filename: string, targetFolderId: string, file: File) => void;
  updateFileProgress: (id: string, progress: number) => void;
  setFileStatus: (id: string, status: PerFileUpload['status'], error?: string) => void;
  removeFile: (id: string) => void;
  cancelFile: (id: string) => void;

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
      if (entry.status === 'uploading' && entry.progress === progress) return state;
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
      next.delete(id);
      return { files: next };
    }),

  reset: () => {
    // Cancel all active uploads before clearing
    const { files } = get();
    for (const entry of files.values()) {
      if (entry.cancelSource && isActiveUpload(entry.status)) {
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
