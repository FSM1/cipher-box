import { useEffect, useRef, useState } from 'react';
import { Portal } from '../ui/Portal';
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
 * Get header title based on upload status.
 */
function getTitle(
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
      return `Uploading (${completedFiles}/${totalFiles})`;
  }
}

/**
 * Collapsible upload popup widget – bottom-right corner.
 *
 * Always rendered in the DOM (via Portal) but visually hidden when idle.
 * Expands automatically when an upload starts, collapses on success after a
 * short delay.  The user can manually toggle expanded/collapsed at any time
 * via the header chevron.
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

  const [expanded, setExpanded] = useState(false);
  const [visible, setVisible] = useState(false);

  const prevStatusRef = useRef(status);
  const autoCollapseTimer = useRef<ReturnType<typeof setTimeout>>();
  const autoHideTimer = useRef<ReturnType<typeof setTimeout>>();

  const isActive = status !== 'idle';
  const canCancel = status === 'encrypting' || status === 'uploading';
  const canClose = status === 'success' || status === 'error' || status === 'cancelled';

  // --- visibility & expand/collapse automation ---
  useEffect(() => {
    const prev = prevStatusRef.current;
    prevStatusRef.current = status;

    // Clear pending timers on every status change
    clearTimeout(autoCollapseTimer.current);
    clearTimeout(autoHideTimer.current);

    if (status !== 'idle' && prev === 'idle') {
      // Upload just started → show & expand
      setVisible(true);
      setExpanded(true);
    }

    if (status === 'success') {
      // Auto-collapse after 1.5s, then hide after the collapse animation (300ms)
      autoCollapseTimer.current = setTimeout(() => {
        setExpanded(false);
        autoHideTimer.current = setTimeout(() => {
          reset();
          setVisible(false);
        }, 400);
      }, 1500);
    }

    return () => {
      clearTimeout(autoCollapseTimer.current);
      clearTimeout(autoHideTimer.current);
    };
  }, [status, reset]);

  // Keep visible flag in sync when store resets externally
  useEffect(() => {
    if (!isActive && !expanded) {
      // Small delay so the collapse animation can finish before we unmount
      const t = setTimeout(() => setVisible(false), 400);
      return () => clearTimeout(t);
    }
    if (isActive) {
      setVisible(true);
    }
    return undefined;
  }, [isActive, expanded]);

  const handleToggle = () => setExpanded((e) => !e);

  const handleClose = () => {
    clearTimeout(autoCollapseTimer.current);
    clearTimeout(autoHideTimer.current);
    setExpanded(false);
    setTimeout(() => {
      reset();
      setVisible(false);
    }, 400);
  };

  const handleCancel = () => cancel();

  const title = getTitle(status, completedFiles, totalFiles);
  const itemStatus = mapStatus(status);

  if (!visible) return null;

  return (
    <Portal>
      <div
        className={`upload-popup ${expanded ? 'upload-popup--expanded' : 'upload-popup--collapsed'}`}
        role="region"
        aria-label="Upload progress"
      >
        {/* Header – always visible, acts as toggle */}
        <button
          type="button"
          className="upload-popup-header"
          onClick={handleToggle}
          aria-expanded={expanded}
        >
          <span className="upload-popup-header-left">
            <span className="upload-popup-icon" aria-hidden="true">
              {status === 'success' ? '\u2713' : status === 'error' ? '!' : '\u2191'}
            </span>
            <span className="upload-popup-title">{isActive ? title : 'Uploads'}</span>
          </span>

          {/* Mini progress indicator visible when collapsed & active */}
          {!expanded && isActive && status !== 'success' && status !== 'error' && (
            <span className="upload-popup-mini-progress">{progress}%</span>
          )}

          <span
            className={`upload-popup-chevron ${expanded ? 'upload-popup-chevron--down' : ''}`}
            aria-hidden="true"
          >
            {'\u25B2'}
          </span>
        </button>

        {/* Body – shown when expanded */}
        <div className="upload-popup-body">
          <div className="upload-popup-progress-bar">
            <div
              className="upload-popup-progress-fill"
              style={{ width: `${progress}%` }}
              data-status={itemStatus}
            />
          </div>

          <div className="upload-popup-overall">
            <span>
              {completedFiles} of {totalFiles} files
            </span>
            <span>{progress}%</span>
          </div>

          {/* Current file being processed */}
          <div className="upload-popup-items">
            {currentFile && (
              <UploadItem
                filename={currentFile}
                status={itemStatus}
                progress={itemStatus === 'complete' ? 100 : progress}
                error={error}
                onCancel={canCancel ? handleCancel : undefined}
              />
            )}

            {status === 'registering' && !currentFile && (
              <div className="upload-item-status">Updating folder metadata...</div>
            )}

            {status === 'error' && error && !currentFile && (
              <div className="upload-zone-error" role="alert">
                {error}
              </div>
            )}
          </div>

          {/* Action buttons */}
          <div className="upload-popup-actions">
            {canCancel && (
              <button
                type="button"
                className="upload-modal-btn upload-modal-btn-cancel"
                onClick={handleCancel}
              >
                Cancel
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
      </div>
    </Portal>
  );
}
