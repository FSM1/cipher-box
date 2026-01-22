import { useCallback, useState } from 'react';
import { useDropzone, FileRejection } from 'react-dropzone';
import { useFileUpload } from '../../hooks/useFileUpload';
import { useFolder } from '../../hooks/useFolder';
import '../../styles/upload.css';

const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB per FILE-01

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
  const { upload, canUpload, isUploading } = useFileUpload();
  const { addFile } = useFolder();
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
        // Other errors
        setError(`Some files were rejected`);
        return;
      }

      if (acceptedFiles.length === 0) {
        return;
      }

      // Calculate total size
      const totalSize = acceptedFiles.reduce((sum, f) => sum + f.size, 0);

      // Check quota
      if (!canUpload(totalSize)) {
        setError('Not enough storage space for these files');
        return;
      }

      try {
        // Upload files to IPFS
        const uploadedFiles = await upload(acceptedFiles);

        // Register each uploaded file in the folder metadata
        // Handle partial failures gracefully - continue with remaining files if one fails
        const failedRegistrations: string[] = [];
        for (const uploaded of uploadedFiles) {
          try {
            await addFile(folderId, {
              cid: uploaded.cid,
              wrappedKey: uploaded.wrappedKey,
              iv: uploaded.iv,
              originalName: uploaded.originalName,
              originalSize: uploaded.originalSize,
            });
          } catch {
            // Keep going, but remember which files failed to register
            failedRegistrations.push(uploaded.originalName ?? 'Unnamed file');
          }
        }

        if (failedRegistrations.length > 0) {
          setError(
            `Some files were uploaded but could not be added to this folder: ${failedRegistrations.join(
              ', '
            )}`
          );
        }

        onUploadComplete?.();
      } catch (err) {
        // Error is already set in upload store
        // Only set local error if not a cancellation
        if ((err as Error).message !== 'Upload cancelled by user') {
          setError((err as Error).message);
        }
      }
    },
    [upload, canUpload, addFile, folderId, onUploadComplete]
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
            {isUploading
              ? 'Uploading...'
              : isDragActive
                ? 'Drop files here'
                : 'Drag files here or click to upload'}
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
