type UploadItemStatus = 'pending' | 'encrypting' | 'uploading' | 'complete' | 'error';

type UploadItemProps = {
  filename: string;
  status: UploadItemStatus;
  progress: number; // 0-100
  error: string | null;
  onCancel?: () => void;
  onRetry?: () => void;
};

/**
 * Get status display text.
 */
function getStatusText(status: UploadItemStatus, progress: number, error: string | null): string {
  switch (status) {
    case 'pending':
      return 'Waiting...';
    case 'encrypting':
      return 'Encrypting...';
    case 'uploading':
      return `Uploading... ${progress}%`;
    case 'complete':
      return 'Complete';
    case 'error':
      return error ?? 'Upload failed';
    default:
      return '';
  }
}

/**
 * Individual file row in upload queue.
 *
 * Shows:
 * - File icon and name
 * - Progress bar
 * - Status text
 * - Cancel button (during encrypting/uploading)
 * - Retry button (on error)
 */
export function UploadItem({
  filename,
  status,
  progress,
  error,
  onCancel,
  onRetry,
}: UploadItemProps) {
  const showCancel = (status === 'encrypting' || status === 'uploading') && onCancel;
  const showRetry = status === 'error' && onRetry;

  return (
    <div className="upload-item">
      <div className="upload-item-header">
        <div className="upload-item-info">
          <span className="upload-item-icon" aria-hidden="true">
            {/* File icon */}
            {'\u{1F4C4}'}
          </span>
          <span className="upload-item-name" title={filename}>
            {filename}
          </span>
        </div>
        <div className="upload-item-actions">
          {showCancel && (
            <button
              type="button"
              className="upload-item-cancel"
              onClick={onCancel}
              aria-label={`Cancel upload of ${filename}`}
            >
              Cancel
            </button>
          )}
          {showRetry && (
            <button
              type="button"
              className="upload-item-retry"
              onClick={onRetry}
              aria-label={`Retry upload of ${filename}`}
            >
              Retry
            </button>
          )}
        </div>
      </div>

      <div className="upload-item-progress-bar">
        <div
          className="upload-item-progress-fill"
          style={{ width: `${progress}%` }}
          data-status={status}
          role="progressbar"
          aria-valuenow={progress}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label={`Upload progress for ${filename}`}
        />
      </div>

      <span className="upload-item-status" data-status={status}>
        {getStatusText(status, progress, error)}
      </span>
    </div>
  );
}
