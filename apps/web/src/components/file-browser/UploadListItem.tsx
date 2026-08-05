import { isActiveUpload, type UploadEntry, type UploadPhase } from '../../hooks/useDropUpload';
import { formatBytes } from '../../utils/format';

interface UploadListItemProps {
  upload: UploadEntry;
  onCancel: (id: string) => void;
  onRetry: (id: string) => void;
  onDismiss: (id: string) => void;
}

/** The phases whose bar can quote a fraction; the rest are indeterminate. */
const MEASURED: readonly UploadPhase[] = ['uploading', 'uploaded'];

const LABELS: Record<UploadPhase, string> = {
  staging: 'sealing',
  queued: 'queued',
  uploading: 'uploading',
  uploaded: 'done',
  stalled: 'retrying',
  cancelled: 'cancelled',
  failed: 'failed',
};

/** One in-flight upload, in the columns the listing below it uses. */
export function UploadListItem({ upload, onCancel, onRetry, onDismiss }: UploadListItemProps) {
  const { id, name, phase, error } = upload;
  const measured = MEASURED.includes(phase);
  const percent = Math.round(upload.progress * 100);
  const settled = !isActiveUpload(phase);

  return (
    <div
      className={`file-list-item upload-row upload-row--${phase}`}
      data-testid="upload-row"
      data-phase={phase}
      role="listitem"
    >
      <div className="file-list-item-row-top">
        <span className="file-list-item-icon" aria-hidden="true">
          {phase === 'failed' ? '[!]' : '[^]'}
        </span>
        <div className="upload-row-name">
          <span className="file-list-item-name">{name}</span>
          {!settled && (
            <div
              className={`upload-row-track${measured ? '' : ' upload-row-track--indeterminate'}`}
              role="progressbar"
              aria-label={`Upload progress for ${name}`}
              {...(measured
                ? { 'aria-valuenow': percent, 'aria-valuemin': 0, 'aria-valuemax': 100 }
                : { 'aria-valuetext': LABELS[phase] })}
            >
              <div className="upload-row-fill" style={{ width: `${measured ? percent : 0}%` }} />
            </div>
          )}
        </div>
      </div>
      <div className="file-list-item-row-bottom">
        <span className="file-list-item-size">{formatBytes(upload.size)}</span>
        <span className="file-list-item-date upload-row-actions">
          <span className="upload-row-status" data-testid="upload-row-status">
            {phase === 'uploading' ? `${percent}%` : LABELS[phase]}
          </span>
          {isActiveUpload(phase) && (
            <button
              type="button"
              className="upload-row-button"
              aria-label={`Cancel upload of ${name}`}
              onClick={() => onCancel(id)}
            >
              [x]
            </button>
          )}
          {phase === 'failed' && (
            <>
              <button
                type="button"
                className="upload-row-button upload-row-button--retry"
                aria-label={`Retry upload of ${name}`}
                onClick={() => onRetry(id)}
              >
                [r]
              </button>
              <button
                type="button"
                className="upload-row-button"
                aria-label={`Dismiss failed upload of ${name}`}
                onClick={() => onDismiss(id)}
              >
                [x]
              </button>
            </>
          )}
        </span>
      </div>
      {error !== null && (
        <p
          className={`upload-row-error${upload.code === 'overBudget' ? ' upload-row-error--budget' : ''}`}
          data-testid="upload-row-error"
          role={phase === 'failed' ? 'alert' : undefined}
        >
          {error}
        </p>
      )}
    </div>
  );
}
