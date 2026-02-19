import { useState, useEffect, useCallback, useRef } from 'react';
import type {
  FolderChild,
  FilePointer,
  FolderEntry,
  FileMetadata,
  VersionEntry,
} from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { useAuthStore } from '../../stores/auth.store';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { downloadFile, triggerBrowserDownload } from '../../services/download.service';
import { useFolder } from '../../hooks/useFolder';
import { formatDate, formatBytes } from '../../utils/format';
import '../../styles/details-dialog.css';

type DetailsDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FolderChild | null;
  folderKey: Uint8Array | null;
  parentFolderId: string;
};

/**
 * Copyable value with a copy button.
 * Shows the full value with word-break and a small copy button.
 */
function CopyableValue({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const timeoutRef = useRef<ReturnType<typeof setTimeout>>();

  useEffect(() => {
    return () => {
      if (timeoutRef.current) clearTimeout(timeoutRef.current);
    };
  }, []);

  const handleCopy = useCallback(async () => {
    if (timeoutRef.current) clearTimeout(timeoutRef.current);
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      // Fallback for older browsers
      const textarea = document.createElement('textarea');
      textarea.value = value;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand('copy');
      document.body.removeChild(textarea);
    }
    setCopied(true);
    timeoutRef.current = setTimeout(() => setCopied(false), 2000);
  }, [value]);

  return (
    <div className="details-copyable">
      <span className="details-copyable-text">{value}</span>
      <button
        type="button"
        className={`details-copy-btn ${copied ? 'details-copy-btn--copied' : ''}`}
        onClick={handleCopy}
        aria-label={copied ? 'Copied to clipboard' : 'Copy to clipboard'}
        aria-pressed={copied}
      >
        {copied ? 'ok' : 'cp'}
      </button>
    </div>
  );
}

/**
 * A single detail row with label and value.
 */
function DetailRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="details-row">
      <span className="details-label">{label}</span>
      {children}
    </div>
  );
}

/**
 * Format a timestamp with time included for version entries.
 */
function formatDateWithTime(timestamp: number): string {
  const date = new Date(timestamp);
  return new Intl.DateTimeFormat(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  }).format(date);
}

/**
 * Version history component for files with past versions.
 * Shows version entries with download, restore, and delete actions.
 */
function VersionHistory({
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

  const handleDownloadVersion = useCallback(
    async (version: VersionEntry) => {
      const privateKey = useAuthStore.getState().vaultKeypair?.privateKey;
      if (!privateKey) return;

      setLoadingAction('download');
      setActionError(null);
      try {
        const decrypted = await downloadFile(
          {
            cid: version.cid,
            iv: version.fileIv,
            wrappedKey: version.fileKeyEncrypted,
            originalName: fileName,
            encryptionMode: version.encryptionMode,
          },
          privateKey
        );
        triggerBrowserDownload(decrypted, fileName);
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
            <div key={`${version.cid}-${version.timestamp}`} className="details-version-entry">
              <div className="details-version-info">
                <span className="details-version-number">v{versionNumber}</span>
                <span className="details-version-date">
                  {formatDateWithTime(version.timestamp)}
                </span>
                <span className="details-version-size">{formatBytes(version.size)}</span>
                <span className="details-version-mode">{version.encryptionMode}</span>
              </div>

              {/* Inline confirm for restore */}
              {confirmingRestore === index ? (
                <div className="details-version-confirm" role="alert">
                  <span className="details-version-confirm-text">
                    Restore version from {formatDate(version.timestamp)}? Current version will be
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

/**
 * File details content (v2: FilePointer with per-file IPNS metadata).
 */
function FileDetails({
  item,
  metadataCid,
  metadataLoading,
  fileMeta,
  fileMetaLoading,
  folderKey,
  parentFolderId,
  onVersionAction,
}: {
  item: FilePointer;
  metadataCid: string | null;
  metadataLoading: boolean;
  fileMeta: FileMetadata | null;
  fileMetaLoading: boolean;
  folderKey: Uint8Array | null;
  parentFolderId: string;
  onVersionAction: () => void;
}) {
  return (
    <div className="details-rows">
      <DetailRow label="Name">
        <span className="details-value">{item.name}</span>
      </DetailRow>

      <DetailRow label="Type">
        <span className="details-type-badge details-type-badge--file">[FILE]</span>
      </DetailRow>

      {/* IPNS section */}
      <div className="details-section-header">{'// ipns'}</div>

      <DetailRow label="File Metadata IPNS">
        <CopyableValue value={item.fileMetaIpnsName} />
      </DetailRow>

      <DetailRow label="Metadata CID">
        {metadataLoading ? (
          <span className="details-loading">resolving...</span>
        ) : metadataCid ? (
          <CopyableValue value={metadataCid} />
        ) : (
          <span className="details-value details-value--dim">unavailable</span>
        )}
      </DetailRow>

      {/* Encryption section */}
      <div className="details-section-header">{'// encryption'}</div>

      <DetailRow label="Mode">
        {fileMetaLoading ? (
          <span className="details-loading">resolving...</span>
        ) : fileMeta ? (
          <span className="details-value">
            AES-256-{fileMeta.encryptionMode}{' '}
            <span className="details-value--dim">
              ({fileMeta.encryptionMode === 'CTR' ? 'streaming' : 'authenticated'})
            </span>
          </span>
        ) : (
          <span className="details-value details-value--dim">unavailable</span>
        )}
      </DetailRow>

      <DetailRow label="File Key">
        {fileMetaLoading ? (
          <span className="details-loading">resolving...</span>
        ) : fileMeta ? (
          <span className="details-value details-value--redacted">
            {fileMeta.fileKeyEncrypted.slice(0, 16)}...{fileMeta.fileKeyEncrypted.slice(-8)}{' '}
            (ECIES-wrapped)
          </span>
        ) : (
          <span className="details-value details-value--dim">unavailable</span>
        )}
      </DetailRow>

      {/* Timestamps */}
      <div className="details-section-header">{'// timestamps'}</div>

      <DetailRow label="Created">
        <span className="details-value">{formatDate(item.createdAt)}</span>
      </DetailRow>

      <DetailRow label="Modified">
        <span className="details-value">{formatDate(item.modifiedAt)}</span>
      </DetailRow>

      {/* Version history (only shown when versions exist) */}
      {fileMeta?.versions && fileMeta.versions.length > 0 && folderKey && (
        <VersionHistory
          versions={fileMeta.versions}
          fileName={item.name}
          folderKey={folderKey}
          parentFolderId={parentFolderId}
          fileId={item.id}
          onRestored={onVersionAction}
        />
      )}
    </div>
  );
}

/**
 * Folder details content.
 */
function FolderDetails({
  item,
  metadataCid,
  metadataLoading,
  sequenceNumber,
  childCount,
}: {
  item: FolderEntry;
  metadataCid: string | null;
  metadataLoading: boolean;
  sequenceNumber: bigint | null;
  childCount: number | null;
}) {
  return (
    <div className="details-rows">
      <DetailRow label="Name">
        <span className="details-value">{item.name}</span>
      </DetailRow>

      <DetailRow label="Type">
        <span className="details-type-badge details-type-badge--folder">[DIR]</span>
      </DetailRow>

      <DetailRow label="Contents">
        {childCount !== null ? (
          <span className="details-value">
            {childCount} {childCount === 1 ? 'item' : 'items'}
          </span>
        ) : (
          <span className="details-value details-value--dim">unknown</span>
        )}
      </DetailRow>

      {/* IPNS section */}
      <div className="details-section-header">{'// ipns'}</div>

      <DetailRow label="IPNS Name">
        <CopyableValue value={item.ipnsName} />
      </DetailRow>

      <DetailRow label="Metadata CID">
        {metadataLoading ? (
          <span className="details-loading">resolving...</span>
        ) : metadataCid ? (
          <CopyableValue value={metadataCid} />
        ) : (
          <span className="details-value details-value--dim">unavailable</span>
        )}
      </DetailRow>

      <DetailRow label="Sequence Number">
        <span className="details-value">
          {sequenceNumber !== null ? sequenceNumber.toString() : '\u2014'}
        </span>
      </DetailRow>

      {/* Crypto section */}
      <div className="details-section-header">{'// encryption'}</div>

      <DetailRow label="Folder Key">
        <span className="details-value details-value--redacted">
          {item.folderKeyEncrypted.slice(0, 16)}...{item.folderKeyEncrypted.slice(-8)}{' '}
          (ECIES-wrapped)
        </span>
      </DetailRow>

      <DetailRow label="IPNS Private Key">
        <span className="details-value details-value--redacted">
          {item.ipnsPrivateKeyEncrypted.slice(0, 16)}...{item.ipnsPrivateKeyEncrypted.slice(-8)}{' '}
          (ECIES-wrapped)
        </span>
      </DetailRow>

      {/* Timestamps */}
      <div className="details-section-header">{'// timestamps'}</div>

      <DetailRow label="Created">
        <span className="details-value">{formatDate(item.createdAt)}</span>
      </DetailRow>

      <DetailRow label="Modified">
        <span className="details-value">{formatDate(item.modifiedAt)}</span>
      </DetailRow>
    </div>
  );
}

/**
 * Details dialog for file/folder metadata.
 *
 * Shows technical information about the selected item:
 * - Files: Content CID, metadata CID, encryption mode, IV, wrapped key, version history
 * - Folders: IPNS name, metadata CID, sequence number, wrapped keys
 *
 * Resolves the parent folder's IPNS record on open to get the live
 * metadata CID. Sensitive key material is displayed in redacted form.
 */
export function DetailsDialog({
  open,
  onClose,
  item,
  folderKey,
  parentFolderId,
}: DetailsDialogProps) {
  const [metadataCid, setMetadataCid] = useState<string | null>(null);
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
  const [fileMetaLoading, setFileMetaLoading] = useState(false);
  // Counter to force re-fetch after version restore/delete
  const [metadataRefresh, setMetadataRefresh] = useState(0);

  // For folders, also look up the folder node for sequence number and child count
  const folderNode = useFolderStore((state) =>
    item?.type === 'folder' ? state.folders[item.id] : undefined
  );

  // Resolve folder IPNS to get metadata CID (folders only)
  useEffect(() => {
    if (!open || !item || item.type !== 'folder') {
      if (!item || item.type !== 'file') {
        setMetadataCid(null);
        setMetadataLoading(false);
      }
      return;
    }

    if (!item.ipnsName) {
      setMetadataLoading(false);
      setMetadataCid(null);
      return;
    }

    let cancelled = false;
    setMetadataLoading(true);

    resolveIpnsRecord(item.ipnsName)
      .then((result) => {
        if (!cancelled) {
          setMetadataCid(result?.cid ?? null);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setMetadataCid(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setMetadataLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, item]);

  // Resolve per-file metadata and CID in a single IPNS call (files only)
  useEffect(() => {
    if (!open || !item || item.type !== 'file' || !folderKey) {
      setFileMeta(null);
      setFileMetaLoading(false);
      // Only reset shared metadataCid when dialog is closed, not when viewing a folder
      if (!open || !item) {
        setMetadataCid(null);
        setMetadataLoading(false);
      }
      return;
    }

    const fileItem = item as FilePointer;
    if (!fileItem.fileMetaIpnsName) {
      setFileMeta(null);
      setFileMetaLoading(false);
      setMetadataCid(null);
      setMetadataLoading(false);
      return;
    }

    let cancelled = false;
    setFileMetaLoading(true);
    setMetadataLoading(true);

    resolveFileMetadata(fileItem.fileMetaIpnsName, folderKey)
      .then(({ metadata, metadataCid: cid }) => {
        if (!cancelled) {
          setFileMeta(metadata);
          setMetadataCid(cid);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setFileMeta(null);
          setMetadataCid(null);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setFileMetaLoading(false);
          setMetadataLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, item, folderKey, metadataRefresh]);

  // Callback to refresh metadata after version restore/delete
  const handleVersionAction = useCallback(() => {
    setMetadataRefresh((prev) => prev + 1);
  }, []);

  if (!item) return null;

  const title = item.type === 'folder' ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {item.type === 'file' ? (
        <FileDetails
          item={item as FilePointer}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          fileMeta={fileMeta}
          fileMetaLoading={fileMetaLoading}
          folderKey={folderKey}
          parentFolderId={parentFolderId}
          onVersionAction={handleVersionAction}
        />
      ) : (
        <FolderDetails
          item={item}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          sequenceNumber={folderNode?.sequenceNumber ?? null}
          childCount={folderNode ? folderNode.children.length : null}
        />
      )}
    </Modal>
  );
}
