import { overBudgetRemedy, type OverBudgetRemedy } from '@cipherbox/client';
import { isActiveUpload, type UploadEntry, type UploadPhase } from '../../hooks/useDropUpload';
import { formatBytes } from '../../utils/format';

interface UploadListItemProps {
  upload: UploadEntry;
  /** Bytes the drain is waiting on before it starts this row's op, or `null`. */
  heldBytes: bigint | null;
  onCancel: (id: string) => void;
  onRetry: (id: string) => void;
  onDismiss: (id: string) => void;
}

// What the user does next about a refused write. The engine's message says
// which budget refused and by how much; this says what to do about it.
const REMEDIES: Record<OverBudgetRemedy, string> = {
  wait: 'Let an upload in progress finish, or cancel one, then try again.',
  freeDeviceSpace: 'Free up space on this device, then try again.',
  freeAccountQuota: 'Free up your CipherBox storage, then try again.',
  nothing: 'Trying again will not help.',
};

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
export function UploadListItem({
  upload,
  heldBytes,
  onCancel,
  onRetry,
  onDismiss,
}: UploadListItemProps) {
  const { id, name, phase, error } = upload;
  const percent = Math.round(upload.progress * 100);
  const settled = !isActiveUpload(phase);
  const held = heldBytes !== null && !settled;
  const measured = phase === 'uploading';
  // Only the row the client is actually feeding animates; a queued or retrying
  // one has nothing moving to report.
  const indeterminate = phase === 'staging';
  const remedy = overBudgetRemedy(upload.code ?? undefined);
  // A refusal something can still clear — the drain, free space, more quota —
  // is a ceiling, not the settled red of a row that will never publish.
  const transient = phase === 'stalled' || (remedy !== undefined && remedy !== 'nothing');
  const retryable = phase !== 'uploaded' && remedy !== 'nothing';
  const label = held ? 'waiting for room' : LABELS[phase];

  return (
    <div
      className={`file-list-item upload-row upload-row--${phase}${held ? ' upload-row--held' : ''}`}
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
                : { 'aria-valuetext': label })}
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
            {measured ? `${percent}%` : label}
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
              {retryable && (
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
      {held && (
        <p className="upload-row-hold" data-testid="upload-row-hold">
          Paused until {formatBytes(Number(heldBytes))} of staging room frees up. This upload
          resumes on its own.
        </p>
      )}
      {error !== null && (
        <p
          className={`upload-row-error${transient ? ' upload-row-error--transient' : ''}`}
          data-testid="upload-row-error"
          role={phase === 'failed' ? 'alert' : undefined}
        >
          {error}
          {remedy !== undefined && (
            <span className="upload-row-remedy" data-testid="upload-row-remedy">
              {' '}
              {REMEDIES[remedy]}
            </span>
          )}
        </p>
      )}
    </div>
  );
}
