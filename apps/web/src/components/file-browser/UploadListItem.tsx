import { useEffect, useRef, useCallback } from 'react';
import { useUploadStore } from '../../stores/upload.store';

type UploadListItemProps = {
  /** Upload entry ID in the upload store */
  fileId: string;
  /** Callback to re-trigger the upload for a failed file (passes the original File object) */
  onRetry?: (file: File) => void;
};

/**
 * Inline upload progress row that matches the FileListItem grid layout.
 *
 * Subscribes to a single file entry via fine-grained Zustand selector
 * so progress updates only re-render this row, not the entire FileList.
 *
 * States:
 * - encrypting: pulsing indeterminate progress bar, cancel button
 * - uploading: determinate progress bar 0-100%, cancel button
 * - complete: green flash for 1s, then removed from store
 * - error: red progress bar, retry + dismiss buttons
 */
export function UploadListItem({ fileId, onRetry }: UploadListItemProps) {
  const file = useUploadStore((s) => s.files.get(fileId));
  const cancelFile = useUploadStore((s) => s.cancelFile);
  const removeFile = useUploadStore((s) => s.removeFile);
  const retryFile = useUploadStore((s) => s.retryFile);

  const completionTimerRef = useRef<ReturnType<typeof setTimeout>>();

  // Auto-remove after 1s green flash on completion (D-05)
  useEffect(() => {
    if (file?.status === 'complete') {
      completionTimerRef.current = setTimeout(() => {
        removeFile(fileId);
      }, 1000);
    }

    return () => {
      if (completionTimerRef.current) {
        clearTimeout(completionTimerRef.current);
      }
    };
  }, [file?.status, fileId, removeFile]);

  const handleCancel = useCallback(() => {
    cancelFile(fileId);
  }, [fileId, cancelFile]);

  const handleDismiss = useCallback(() => {
    removeFile(fileId);
  }, [fileId, removeFile]);

  const handleRetry = useCallback(() => {
    retryFile(fileId);
    if (file?.file && onRetry) {
      onRetry(file.file);
    }
  }, [fileId, retryFile, file?.file, onRetry]);

  if (!file) return null;

  const isError = file.status === 'error';
  const isComplete = file.status === 'complete';
  const isEncrypting = file.status === 'encrypting';

  const rowClassName = [
    'file-list-item',
    'upload-inline-row',
    isError ? 'upload-inline-row--error' : '',
    isComplete ? 'upload-inline-row--complete' : '',
  ]
    .filter(Boolean)
    .join(' ');

  return (
    <div className={rowClassName} role="row">
      <div className="file-list-item-row-top" role="gridcell">
        <span className="file-list-item-icon upload-inline-icon" aria-hidden="true">
          {isError ? '[!]' : '[^]'}
        </span>
        <div className="upload-inline-name-wrapper">
          <span className="file-list-item-name">{file.filename}</span>
          <div
            className={`upload-inline-progress-track ${isEncrypting ? 'upload-inline-progress-track--pulse' : ''}`}
          >
            <div
              className="upload-inline-progress-fill"
              style={{ width: `${file.progress}%` }}
              data-status={file.status}
              role="progressbar"
              aria-valuenow={file.progress}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label={`Upload progress for ${file.filename}`}
            />
          </div>
        </div>
      </div>

      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          {'--'}
        </span>
        <span className="file-list-item-date upload-inline-actions" role="gridcell">
          {!isComplete && !isError && (
            <button
              type="button"
              className="upload-inline-btn"
              onClick={handleCancel}
              aria-label={`Cancel upload of ${file.filename}`}
              title="Cancel upload"
            >
              {'[x]'}
            </button>
          )}
          {isError && (
            <>
              <button
                type="button"
                className="upload-inline-btn upload-inline-btn--retry"
                onClick={handleRetry}
                aria-label={`Retry upload of ${file.filename}`}
                title="Retry upload"
              >
                {'[R]'}
              </button>
              <button
                type="button"
                className="upload-inline-btn"
                onClick={handleDismiss}
                aria-label={`Dismiss failed upload of ${file.filename}`}
                title="Dismiss error"
              >
                {'[x]'}
              </button>
            </>
          )}
        </span>
      </div>
    </div>
  );
}
