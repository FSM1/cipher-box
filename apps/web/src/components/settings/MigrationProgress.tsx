import { useCallback, useEffect, useRef, useState } from 'react';
import { migrationApi, type MigrationStatus } from '../../lib/api/migration';

/**
 * Migration progress UI for the STORAGE tab.
 *
 * Polls migration status every 5 seconds while a migration is active.
 * Shows progress bar with migrated/total count, failed count in error color,
 * and pause/resume/cancel controls with cancel confirmation dialog.
 */
export function MigrationProgress() {
  const [migration, setMigration] = useState<MigrationStatus | null>(null);
  const [showCancelConfirm, setShowCancelConfirm] = useState(false);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const TERMINAL_STATUSES = ['completed', 'failed', 'cancelled'];

  const fetchStatus = useCallback(async () => {
    const status = await migrationApi.getStatus();
    // Only update state if values actually changed to avoid no-op re-renders
    setMigration((prev) => {
      if (!status && !prev) return prev;
      if (
        prev &&
        status &&
        prev.status === status.status &&
        prev.migratedCids === status.migratedCids &&
        prev.failedCids === status.failedCids
      ) {
        return prev;
      }
      return status;
    });
    return status;
  }, []);

  // Single-flight recursive setTimeout avoids overlapping polls
  useEffect(() => {
    let cancelled = false;
    async function poll() {
      const status = await fetchStatus();
      if (cancelled) return;
      // Stop polling on terminal state; keep polling on null (migration may start)
      if (status && TERMINAL_STATUSES.includes(status.status)) return;
      pollRef.current = setTimeout(poll, 5000);
    }
    poll();
    return () => {
      cancelled = true;
      if (pollRef.current) clearTimeout(pollRef.current);
    };
  }, [fetchStatus]);

  if (!migration || migration.status === 'cancelled') return null;

  const percentage =
    migration.totalCids > 0 ? (migration.migratedCids / migration.totalCids) * 100 : 0;

  const isActive = migration.status === 'running' || migration.status === 'pending';
  const isPaused = migration.status === 'paused';
  const isComplete = migration.status === 'completed';

  const handlePause = async () => {
    await migrationApi.pause(migration.id);
    fetchStatus();
  };

  const handleResume = async () => {
    await migrationApi.resume(migration.id);
    fetchStatus();
  };

  const handleCancel = async () => {
    await migrationApi.cancel(migration.id);
    setShowCancelConfirm(false);
    fetchStatus();
  };

  return (
    <div className="migration-progress">
      <h3 className="settings-section-heading">{'// pin migration'}</h3>
      <p className="settings-section-description">
        {
          'migrate existing pins between providers. data is transferred via tee -- your encryption keys are never exposed.'
        }
      </p>

      {/* Progress bar */}
      <div
        className="migration-progress-bar"
        role="progressbar"
        aria-valuenow={migration.migratedCids}
        aria-valuemin={0}
        aria-valuemax={migration.totalCids}
        aria-label="Pin migration progress"
      >
        <div
          className="migration-progress-fill"
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>

      {/* Progress text */}
      {isComplete ? (
        <p className="migration-progress-text migration-complete">
          {`> migration complete. ${migration.totalCids} pins transferred.`}
        </p>
      ) : (
        <p className="migration-progress-text">
          {`migrating: ${migration.migratedCids}/${migration.totalCids} pins`}
        </p>
      )}

      {/* Failed count */}
      {migration.failedCids > 0 && (
        <p className="migration-failed-text">{`${migration.failedCids} pins failed`}</p>
      )}

      {/* Controls */}
      {(isActive || isPaused) && (
        <div className="migration-controls">
          {isActive && (
            <button type="button" className="storage-discard-btn" onClick={handlePause}>
              {'[--pause migration]'}
            </button>
          )}
          {isPaused && (
            <button type="button" className="storage-discard-btn" onClick={handleResume}>
              {'[--resume migration]'}
            </button>
          )}

          {showCancelConfirm ? (
            <div className="migration-cancel-confirm">
              <p className="migration-cancel-text">
                {`cancel migration: ${migration.migratedCids}/${migration.totalCids} pins transferred. pins already migrated will remain on the new provider. cancel?`}
              </p>
              <button type="button" className="storage-discard-btn" onClick={handleCancel}>
                {'[--confirm cancel]'}
              </button>
              <button
                type="button"
                className="storage-discard-btn"
                onClick={() => setShowCancelConfirm(false)}
              >
                {'[--keep migrating]'}
              </button>
            </div>
          ) : (
            <button
              type="button"
              className="storage-discard-btn"
              onClick={() => setShowCancelConfirm(true)}
            >
              {'[--cancel migration]'}
            </button>
          )}
        </div>
      )}
    </div>
  );
}
