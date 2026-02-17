import { useState, useEffect, useCallback, useRef } from 'react';
import type { FolderChildV2, FilePointer, FolderEntry } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useFolderStore } from '../../stores/folder.store';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { formatDate } from '../../utils/format';
import '../../styles/details-dialog.css';

type DetailsDialogProps = {
  open: boolean;
  onClose: () => void;
  item: FolderChildV2 | null;
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
}: {
  item: FilePointer;
  metadataCid: string | null;
  metadataLoading: boolean;
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
export function DetailsDialog({ open, onClose, item }: DetailsDialogProps) {
  const [metadataCid, setMetadataCid] = useState<string | null>(null);
  const [metadataLoading, setMetadataLoading] = useState(false);

  // For folders, also look up the folder node for sequence number and child count
  const folderNode = useFolderStore((state) =>
    item?.type === 'folder' ? state.folders[item.id] : undefined
  );

  // Resolve IPNS to get metadata CID when dialog opens
  useEffect(() => {
    if (!open || !item) {
      setMetadataCid(null);
      return;
    }

    const ipnsName =
      item.type === 'folder' ? item.ipnsName : (item as FilePointer).fileMetaIpnsName;

    if (!ipnsName) {
      setMetadataLoading(false);
      setMetadataCid(null);
      return;
    }

    let cancelled = false;
    setMetadataLoading(true);

    resolveIpnsRecord(ipnsName)
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

  if (!item) return null;

  const title = item.type === 'folder' ? 'Folder Details' : 'File Details';

  return (
    <Modal open={open} onClose={onClose} title={title}>
      {item.type === 'file' ? (
        <FileDetails item={item} metadataCid={metadataCid} metadataLoading={metadataLoading} />
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
