import type { FilePointer, FileMetadata } from '@cipherbox/core';
import { formatDate } from '../../../utils/format';
import { CopyableValue, DetailRow } from './DetailsPrimitives';
import { VersionHistory } from './VersionHistory';

/**
 * File details content (v2: FilePointer with per-file IPNS metadata).
 */
export function FileDetails({
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
