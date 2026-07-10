import { useState, useCallback } from 'react';
import type { VersionEntry } from '@cipherbox/core';
import { decryptAesGcm, decryptAesCtr } from '@cipherbox/crypto';
import { useFolder } from '../../../hooks/useFolder';
import { formatDate, formatBytes } from '../../../utils/format';
import { formatDateWithTime } from './DetailsPrimitives';
import { getSdkClient } from '../../../lib/sdk-provider';
import { triggerBrowserDownload } from '../../../services/download.service';

/** Decodes a base64 string to a Uint8Array (VersionEntry.fileIv is base64, v3 contract). */
function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }
  return bytes;
}

/**
 * Version history component for files with past versions.
 * Shows version entries with download, restore, and delete actions.
 */
export function VersionHistory({
  versions,
  fileName,
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

  /**
   * Download a specific past version.
   *
   * Each `VersionEntry` is self-contained (raw `fileKey`, base64 `fileIv`,
   * `cid`, `encryptionMode` — NODE-02) — no read-chain resolve is needed
   * beyond what the caller already provided via `versions`.
   */
  const handleDownloadVersion = useCallback(
    async (version: VersionEntry, index: number) => {
      setLoadingAction(`download-${index}`);
      setActionError(null);
      try {
        const ciphertext = await getSdkClient().downloadBytes(version.cid);
        const iv = base64ToBytes(version.fileIv);
        const plaintext =
          version.encryptionMode === 'CTR'
            ? await decryptAesCtr(ciphertext, version.fileKey, iv)
            : await decryptAesGcm(ciphertext, version.fileKey, iv);
        triggerBrowserDownload(plaintext, fileName);
      } catch {
        setActionError('Failed to download version');
      } finally {
        setLoadingAction(null);
      }
    },
    [fileName]
  );

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
                  {formatDateWithTime(version.createdAt)}
                </span>
                <span className="details-version-size">{formatBytes(version.size)}</span>
                <span className="details-version-mode">{version.encryptionMode}</span>
              </div>

              {/* Inline confirm for restore */}
              {confirmingRestore === index ? (
                <div className="details-version-confirm" role="alert">
                  <span className="details-version-confirm-text">
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
                    onClick={() => handleDownloadVersion(version, index)}
                    disabled={isLoading}
                    aria-label={`Download version ${versionNumber}`}
                  >
                    {loadingAction === `download-${index}` ? '...' : 'dl'}
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
