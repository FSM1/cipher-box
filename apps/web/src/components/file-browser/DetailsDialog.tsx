import { useState, useEffect, useCallback, useRef } from 'react';
import type { FolderChildV2, FilePointer, FolderEntry, FileMetadata } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { formatDate } from '../../utils/format';
import '../../styles/details-dialog.css';

type DetailsDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FolderChildV2 | null;
  folderKey: Uint8Array | null;
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
 * File details content (v2: FilePointer with per-file IPNS metadata).
 */
function FileDetails({
  item,
  metadataCid,
  metadataLoading,
  fileMeta,
  fileMetaLoading,
}: {
  item: FilePointer;
  metadataCid: string | null;
  metadataLoading: boolean;
  fileMeta: FileMetadata | null;
  fileMetaLoading: boolean;
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
          {sequenceNumber !== null ? sequenceNumber.toString() : '—'}
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
 * - Files: Content CID, metadata CID, encryption mode, IV, wrapped key
 * - Folders: IPNS name, metadata CID, sequence number, wrapped keys
 *
 * Resolves the parent folder's IPNS record on open to get the live
 * metadata CID. Sensitive key material is displayed in redacted form.
 */
export function DetailsDialog({ open, onClose, item, folderKey }: DetailsDialogProps) {
  const [metadataCid, setMetadataCid] = useState<string | null>(null);
  const [metadataLoading, setMetadataLoading] = useState(false);
  const [fileMeta, setFileMeta] = useState<FileMetadata | null>(null);
  const [fileMetaLoading, setFileMetaLoading] = useState(false);

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

    let cancelled = false;
    setFileMetaLoading(true);
    setMetadataLoading(true);

    resolveFileMetadata(item.fileMetaIpnsName, folderKey)
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
  }, [open, item, folderKey]);

  if (!item) return null;

  const title = item.type === 'folder' ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {item.type === 'file' ? (
        <FileDetails
          item={item}
          metadataCid={metadataCid}
          metadataLoading={metadataLoading}
          fileMeta={fileMeta}
          fileMetaLoading={fileMetaLoading}
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
