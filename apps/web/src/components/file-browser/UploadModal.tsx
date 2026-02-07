import { useEffect, useRef } from 'react';
import { Modal } from '../ui/Modal';
import { UploadItem } from './UploadItem';
import { useUploadStore } from '../../stores/upload.store';
import '../../styles/upload.css';

/**
 * Map upload store status to display status.
 */
function mapStatus(
  storeStatus: ReturnType<typeof useUploadStore.getState>['status']
): 'pending' | 'encrypting' | 'uploading' | 'complete' | 'error' {
  switch (storeStatus) {
    case 'encrypting':
      return 'encrypting';
    case 'uploading':
      return 'uploading';
    case 'success':
      return 'complete';
    case 'error':
    case 'cancelled':
      return 'error';
    default:
      return 'pending';
  }
}

/**
 * Get modal title based on upload status.
 */
function getModalTitle(
  status: ReturnType<typeof useUploadStore.getState>['status'],
  completedFiles: number,
  totalFiles: number
): string {
  switch (status) {
    case 'success':
      return 'Upload Complete';
    case 'error':
      return 'Upload Failed';
    case 'cancelled':
      return 'Upload Cancelled';
    case 'registering':
      return 'Registering Files...';
    default:
      return `Uploading Files (${completedFiles}/${totalFiles})`;
  }
}

/**
 * Upload progress modal showing upload queue.
 *
 * Features:
 * - Shows current file being uploaded with progress bar
 * - Shows overall progress (X of Y files)
 * - Cancel button to stop all uploads
 * - Close button after completion/error
 * - Error state with descriptive message
 *
 * Per CONTEXT.md v1 simplification:
 * - Shows current file progress + overall batch progress
 * - Individual file tracking can be enhanced in future
 */
export function UploadModal() {
  const status = useUploadStore((state) => state.status);
  const progress = useUploadStore((state) => state.progress);
  const currentFile = useUploadStore((state) => state.currentFile);
  const totalFiles = useUploadStore((state) => state.totalFiles);
  const completedFiles = useUploadStore((state) => state.completedFiles);
  const error = useUploadStore((state) => state.error);
  const cancel = useUploadStore((state) => state.cancel);
  const reset = useUploadStore((state) => state.reset);

  const isVisible = status !== 'idle';

  // Can close when upload is finished (success, error, cancelled)
  const canClose = status === 'success' || status === 'error' || status === 'cancelled';

  // Can cancel only during active upload
  const canCancel = status === 'encrypting' || status === 'uploading';

  // Auto-dismiss after 1.5s on success
  const autoCloseTimer = useRef<ReturnType<typeof setTimeout>>();
  useEffect(() => {
    if (status === 'success') {
      autoCloseTimer.current = setTimeout(() => {
        reset();
      }, 1500);
    }
    return () => clearTimeout(autoCloseTimer.current);
  }, [status, reset]);

  const handleClose = () => {
    clearTimeout(autoCloseTimer.current);
    reset();
  };

  const handleCancel = () => {
    cancel();
  };

  const title = getModalTitle(status, completedFiles, totalFiles);
  const itemStatus = mapStatus(status);

  return (
    <Modal open={isVisible} title={title} onClose={canClose ? handleClose : undefined}>
      <div className="upload-modal-content">
        {/* Overall progress */}
        <div className="upload-modal-progress">
          <div className="upload-modal-overall">
            <span>
              {completedFiles} of {totalFiles} files uploaded
            </span>
            <span>{progress}%</span>
          </div>
        </div>

        {/* Current file being processed */}
        <div className="upload-item-list">
          {currentFile && (
            <UploadItem
              filename={currentFile}
              status={itemStatus}
              progress={itemStatus === 'complete' ? 100 : progress}
              error={error}
              onCancel={canCancel ? handleCancel : undefined}
            />
          )}

          {/* Show status message during registering */}
          {status === 'registering' && !currentFile && (
            <div className="upload-item-status">Updating folder metadata...</div>
          )}

          {/* Show error message if upload failed */}
          {status === 'error' && error && !currentFile && (
            <div className="upload-zone-error" role="alert">
              {error}
            </div>
          )}
        </div>

        {/* Action buttons */}
        <div className="upload-modal-actions">
          {canCancel && (
            <button
              type="button"
              className="upload-modal-btn upload-modal-btn-cancel"
              onClick={handleCancel}
            >
              Cancel All
            </button>
          )}
          {canClose && (
            <button
              type="button"
              className="upload-modal-btn upload-modal-btn-close"
              onClick={handleClose}
            >
              Close
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}
