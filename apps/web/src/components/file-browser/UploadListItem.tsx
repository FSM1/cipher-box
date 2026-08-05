import { isActiveUpload, type UploadEntry, type UploadPhase } from '../../hooks/useDropUpload';
import { formatBytes } from '../../utils/format';

interface UploadListItemProps {
  upload: UploadEntry;
  onCancel: (id: string) => void;
  onRetry: (id: string) => void;
  onDismiss: (id: string) => void;
}

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
  const measured = phase === 'uploading' || phase === 'uploaded';
  const percent = Math.round(upload.progress * 100);
  const settled = !isActiveUpload(phase);
  // Only the row the client is actually feeding animates; a queued or retrying
  // one has nothing moving to report.
  const indeterminate = phase === 'staging';
  // An over-budget refusal is a ceiling and a stopped attempt is retried, so
  // neither reads as the settled red of a row that will never publish.
  const transient = phase === 'stalled' || upload.code === 'overBudget';

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
              className={`upload-row-track${indeterminate ? ' upload-row-track--indeterminate' : ''}`}
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
          {!settled && (
            <button
              type="button"
              className="upload-row-button"
              aria-label={`Cancel upload of ${name}`}
              onClick={() => onCancel(id)}
            >
              [x]
            </button>
          )}
          {settled && (
            <>
              {phase !== 'uploaded' && (
                <button
                  type="button"
                  className="upload-row-button upload-row-button--retry"
                  aria-label={`Retry upload of ${name}`}
                  onClick={() => onRetry(id)}
                >
                  [r]
                </button>
              )}
              {/* Every settled row is clearable, so none can strand its `File`. */}
              <button
                type="button"
                className="upload-row-button"
                aria-label={`Dismiss upload of ${name}`}
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
          className={`upload-row-error${transient ? ' upload-row-error--transient' : ''}`}
          data-testid="upload-row-error"
          role={phase === 'failed' ? 'alert' : undefined}
        >
          {error}
        </p>
      )}
    </div>
  );
}
