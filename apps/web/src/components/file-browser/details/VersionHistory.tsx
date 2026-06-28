import { useState, useCallback } from 'react';
import type { VersionEntry } from '@cipherbox/core';
import { useFolder } from '../../../hooks/useFolder';
import { formatDate, formatBytes } from '../../../utils/format';
import { formatDateWithTime } from './DetailsPrimitives';

/**
 * Version history component for files with past versions.
 * Shows version entries with download, restore, and delete actions.
 */
export function VersionHistory({
  versions,
  fileName: _fileName, // TODO(phase 65): used for download trigger stub
  folderKey,
  parentFolderId,
  fileId,
  onRestored,
}: {
  versions: VersionEntry[];
  fileName: string;
  folderKey: Uint8Array;
  parentFolderId: string;
  fileId: string;
  onRestored: () => void;
}) {
  const { restoreVersion, deleteVersion } = useFolder();
  const [confirmingRestore, setConfirmingRestore] = useState<number | null>(null);
  const [confirmingDelete, setConfirmingDelete] = useState<number | null>(null);
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const handleDownloadVersion = useCallback(async (_version: VersionEntry) => {
    // TODO(phase 65): VersionEntry.fileKey is now a raw Uint8Array inside the sealed body;
    // the download path needs the Node read-chain to obtain it (phase 63/65).
    throw new Error('not implemented — phase 65 (version download via Node read-chain)');
  }, []);

  const handleRestore = useCallback(
    async (versionIndex: number) => {
      setLoadingAction(`restore-${versionIndex}`);
      setActionError(null);
      setConfirmingRestore(null);
      try {
        await restoreVersion(parentFolderId, fileId, versionIndex);
        onRestored();
      } catch {
        setActionError('Failed to restore version');
      } finally {
        setLoadingAction(null);
      }
    },
    [restoreVersion, parentFolderId, fileId, onRestored]
  );

  const handleDelete = useCallback(
    async (versionIndex: number) => {
      setLoadingAction(`delete-${versionIndex}`);
      setActionError(null);
      setConfirmingDelete(null);
      try {
        await deleteVersion(parentFolderId, fileId, versionIndex);
        onRestored();
      } catch {
        setActionError('Failed to delete version');
      } finally {
        setLoadingAction(null);
      }
    },
    [deleteVersion, parentFolderId, fileId, onRestored]
  );

  // Dismiss unused param lint -- folderKey is passed for future use
  void folderKey;

  return (
    <div className="details-version-section">
      <div className="details-section-header">{'// version history'}</div>

      {actionError && (
        <div className="details-version-error" role="alert">
          {actionError}
        </div>
      )}

      <div className="details-version-list">
        {versions.map((version, index) => {
          // v1 = oldest, vN = newest (reversed display numbering)
          const versionNumber = versions.length - index;
          const isLoading = loadingAction !== null;

          return (
            <div key={`${version.cid}-${version.createdAt}`} className="details-version-entry">
              <div className="details-version-info">
                <span className="details-version-number">v{versionNumber}</span>
                <span className="details-version-date">
                  {/* TODO(phase 63): version.createdAt (ms) replaces retired version.timestamp */}
                  {formatDateWithTime(version.createdAt)}
                </span>
                <span className="details-version-size">{formatBytes(version.size)}</span>
                <span className="details-version-mode">{version.encryptionMode}</span>
              </div>

              {/* Inline confirm for restore */}
              {confirmingRestore === index ? (
                <div className="details-version-confirm" role="alert">
                  <span className="details-version-confirm-text">
                    {/* TODO(phase 63): version.createdAt (ms) replaces retired version.timestamp */}
                    Restore version from {formatDate(version.createdAt)}? Current version will be
                    saved as a past version.
                  </span>
                  <div className="details-version-confirm-actions">
                    <button
                      type="button"
                      className="details-version-confirm-btn details-version-confirm-btn--yes"
                      onClick={() => handleRestore(index)}
                      aria-label="Confirm restore"
                    >
                      confirm
                    </button>
                    <button
                      type="button"
                      className="details-version-confirm-btn details-version-confirm-btn--no"
                      onClick={() => setConfirmingRestore(null)}
                      aria-label="Cancel restore"
                    >
                      cancel
                    </button>
                  </div>
                </div>
              ) : confirmingDelete === index ? (
                <div className="details-version-confirm" role="alert">
                  <span className="details-version-confirm-text">
                    Delete this version? This cannot be undone.
                  </span>
                  <div className="details-version-confirm-actions">
                    <button
                      type="button"
                      className="details-version-confirm-btn details-version-confirm-btn--yes"
                      onClick={() => handleDelete(index)}
                      aria-label="Confirm delete"
                    >
                      confirm
                    </button>
                    <button
                      type="button"
                      className="details-version-confirm-btn details-version-confirm-btn--no"
                      onClick={() => setConfirmingDelete(null)}
                      aria-label="Cancel delete"
                    >
                      cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="details-version-actions">
                  <button
                    type="button"
                    className="details-version-btn"
                    onClick={() => handleDownloadVersion(version)}
                    disabled={isLoading}
                    aria-label={`Download version ${versionNumber}`}
                  >
                    {loadingAction === 'download' ? '...' : 'dl'}
                  </button>
                  <button
                    type="button"
                    className="details-version-btn details-version-btn--restore"
                    onClick={() => {
                      setConfirmingRestore(index);
                      setConfirmingDelete(null);
                    }}
                    disabled={isLoading}
                    aria-label={`Restore version ${versionNumber}`}
                  >
                    {loadingAction === `restore-${index}` ? '...' : 'restore'}
                  </button>
                  <button
                    type="button"
                    className="details-version-btn details-version-btn--delete"
                    onClick={() => {
                      setConfirmingDelete(index);
                      setConfirmingRestore(null);
                    }}
                    disabled={isLoading}
                    aria-label={`Delete version ${versionNumber}`}
                  >
                    {loadingAction === `delete-${index}` ? '...' : 'rm'}
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
