import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useFolder } from '../../hooks/useFolder';
import { useUploadStore } from '../../stores/upload.store';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB per FILE-01

/**
 * Terminal-style ASCII art for empty state using box-drawing characters.
 * Shows a mini terminal window with `ls -la` returning empty results.
 */
const terminalArt = `\u250C\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510
\u2502 $ ls -la             \u2502
\u2502 total 0              \u2502
\u2502 $ \u2588                  \u2502
\u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518`;

type EmptyStateProps = {
  folderId: string;
};

export function EmptyState({ folderId }: EmptyStateProps) {
  const { upload, canUpload, isUploading } = useFileUpload();
  const { addFiles } = useFolder();
  const [error, setError] = useState<string | null>(null);

  const handleDrop = useCallback(
    async (acceptedFiles: File[], rejectedFiles: FileRejection[]) => {
      setError(null);

      if (rejectedFiles.length > 0) {
        const oversized = rejectedFiles.filter((r) =>
          r.errors.some((e) => e.code === 'file-too-large')
        );
        if (oversized.length > 0) {
          setError(`Files exceed 100MB limit: ${oversized.map((r) => r.file.name).join(', ')}`);
          return;
        }
        setError('Some files were rejected');
        return;
      }

      if (acceptedFiles.length === 0) return;

      const totalSize = acceptedFiles.reduce((sum, f) => sum + f.size, 0);
      if (!canUpload(totalSize)) {
        setError('Not enough storage space for these files');
        return;
      }

      try {
        // Upload files to IPFS (sequential encrypt + upload per file)
        const uploadedFiles = await upload(acceptedFiles);

        // Set registering status during batch folder metadata registration
        useUploadStore.getState().setRegistering();

        // Batch register all files in folder (single IPNS publish)
        await addFiles(
          folderId,
          uploadedFiles.map((uploaded) => ({
            cid: uploaded.cid,
            wrappedKey: uploaded.wrappedKey,
            iv: uploaded.iv,
            originalName: uploaded.originalName,
            originalSize: uploaded.originalSize,
          }))
        );
      } catch (err) {
        if ((err as Error).message !== 'Upload cancelled by user') {
          setError((err as Error).message);
        }
      }
    },
    [upload, canUpload, addFiles, folderId]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: handleDrop,
    noClick: false,
    multiple: true,
    maxSize: MAX_FILE_SIZE,
  });

  const classes = ['empty-state'];
  if (isDragActive) classes.push('empty-state-drag-active');
  if (isUploading) classes.push('empty-state-uploading');

  return (
    <div {...getRootProps({ className: classes.join(' ') })} data-testid="empty-state">
      <input {...getInputProps()} />
      <div className="empty-state-content">
        <pre className="empty-state-ascii" aria-hidden="true">
          {terminalArt}
        </pre>
        <p className="empty-state-text">
          {isUploading ? '// UPLOADING...' : isDragActive ? '// DROP FILES' : '// EMPTY DIRECTORY'}
        </p>
        <p className="empty-state-hint">drag files here or use --upload</p>
      </div>
      {error && (
        <div className="upload-zone-error" role="alert">
          {error}
          <button
            type="button"
            className="upload-zone-error-dismiss"
            onClick={(e) => {
              e.stopPropagation();
              setError(null);
            }}
            aria-label="Dismiss error"
          >
            &times;
          </button>
        </div>
      )}
    </div>
  );
}
