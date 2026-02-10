import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { useDropUpload, MAX_FILE_SIZE } from '../../hooks/useDropUpload';
import { useFileUpload } from '../../hooks/useFileUpload';
import '../../styles/upload.css';

type UploadZoneProps = {
  folderId: string;
  onUploadComplete?: () => void;
};

/**
 * Drag-drop upload zone component.
 *
 * Features:
 * - Drag files to upload
 * - Click to open file picker
 * - Pre-checks quota before upload
 * - Shows visual feedback on drag over
 * - Enforces 100MB max file size per FILE-01
 *
 * @example
 * ```tsx
 * <UploadZone
 *   folderId={currentFolder.id}
 *   onUploadComplete={() => refreshFolder()}
 * />
 * ```
 */
export function UploadZone({ folderId, onUploadComplete }: UploadZoneProps) {
  const { handleFileDrop } = useDropUpload();
  const { isUploading } = useFileUpload();
  const [error, setError] = useState<string | null>(null);

  const handleDrop = useCallback(
    async (acceptedFiles: File[], rejectedFiles: FileRejection[]) => {
      setError(null);

      // Handle rejected files (too large)
      if (rejectedFiles.length > 0) {
        const oversized = rejectedFiles.filter((r) =>
          r.errors.some((e) => e.code === 'file-too-large')
        );
        if (oversized.length > 0) {
          setError(`Files exceed 100MB limit: ${oversized.map((r) => r.file.name).join(', ')}`);
          return;
        }
        setError(`Some files were rejected`);
        return;
      }

      if (acceptedFiles.length === 0) return;

      try {
        await handleFileDrop(acceptedFiles, folderId);
        onUploadComplete?.();
      } catch (err) {
        setError((err as Error).message);
      }
    },
    [handleFileDrop, folderId, onUploadComplete]
  );

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop: handleDrop,
    noClick: false, // Allow click to open file dialog
    multiple: true, // Allow multiple files
    maxSize: MAX_FILE_SIZE,
  });

  const zoneClasses = ['upload-zone'];
  if (isDragActive) {
    zoneClasses.push('upload-zone-active');
  }
  if (isUploading) {
    zoneClasses.push('upload-zone-uploading');
  }

  return (
    <div className="upload-zone-wrapper">
      <div {...getRootProps({ className: zoneClasses.join(' ') })}>
        <input {...getInputProps()} />
        <div className="upload-zone-content">
          <span className="upload-zone-icon" aria-hidden="true">
            {/* Unicode upload icon */}
            {'\u2B06'}
          </span>
          <p className="upload-zone-text">
            {isUploading ? 'uploading...' : isDragActive ? 'drop files here' : '--upload'}
          </p>
        </div>
      </div>
      {error && (
        <div className="upload-zone-error" role="alert">
          {error}
          <button
            type="button"
            className="upload-zone-error-dismiss"
            onClick={() => setError(null)}
            aria-label="Dismiss error"
          >
            &times;
          </button>
        </div>
      )}
    </div>
  );
}
