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

  // Timer ref for completion flash (D-05, D-06)
  const completionTimerRef = useRef<ReturnType<typeof setTimeout>>();

  // When status becomes 'complete', start 1000ms timer then remove (D-05)
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

  if (!file) return null;

  const isError = file.status === 'error';
  const isComplete = file.status === 'complete';
  const isEncrypting = file.status === 'encrypting';

  // Cancel handler: cancel the network request and remove from UI immediately (D-07, D-08)
  const handleCancel = useCallback(() => {
    cancelFile(fileId);
    removeFile(fileId);
  }, [fileId, cancelFile, removeFile]);

  // Dismiss handler: remove failed upload row from UI (D-10)
  const handleDismiss = useCallback(() => {
    removeFile(fileId);
  }, [fileId, removeFile]);

  // Retry handler: reset visual state AND re-trigger the actual upload (D-09)
  const handleRetry = useCallback(() => {
    retryFile(fileId);
    if (file?.file && onRetry) {
      onRetry(file.file);
    }
  }, [fileId, retryFile, file?.file, onRetry]);

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
      {/* Row top: icon + name + progress bar */}
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

      {/* Row bottom: size + date/actions */}
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size" role="gridcell">
          {'--'}
        </span>
        <span className="file-list-item-date upload-inline-actions" role="gridcell">
          {/* Cancel button -- visible during encrypting/uploading */}
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
          {/* Error state -- retry + dismiss */}
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
