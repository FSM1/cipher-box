import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { useDropUpload, MAX_FILE_SIZE } from '../../hooks/useDropUpload';
import { useFileUpload } from '../../hooks/useFileUpload';

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
  const { handleFileDrop } = useDropUpload();
  const { isUploading } = useFileUpload();
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

      try {
        await handleFileDrop(acceptedFiles, folderId);
      } catch (err) {
        setError((err as Error).message);
      }
    },
    [handleFileDrop, folderId]
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
