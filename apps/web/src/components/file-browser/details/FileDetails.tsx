import type { NodeContent } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';
import { formatDate } from '../../../utils/format';
import { CopyableValue, DetailRow } from './DetailsPrimitives';
import { VersionHistory } from './VersionHistory';

/**
 * File details content (node/v3: ResolvedChild display; content resolved via read-chain).
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
  item: ResolvedChild;
  metadataCid: string | null;
  metadataLoading: boolean;
  /** NodeContent resolved via read-chain — null until phase-63 read-chain lands. */
  fileMeta: NodeContent | null;
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
          <span className="details-value details-value--redacted">[redacted]</span>
        ) : (
          <span className="details-value details-value--dim">unavailable</span>
        )}
      </DetailRow>

      {/* Timestamps */}
      <div className="details-section-header">{'// timestamps'}</div>

      <DetailRow label="Created">
        {/* TODO(phase 63): SealedChildRef has no createdAt; resolve from Node envelope */}
        <span className="details-value details-value--dim">unavailable (phase 63)</span>
      </DetailRow>

      <DetailRow label="Modified">
        {typeof item.modifiedAt === 'number' && Number.isFinite(item.modifiedAt) ? (
          <span className="details-value">{formatDate(item.modifiedAt)}</span>
        ) : (
          <span className="details-value details-value--dim">—</span>
        )}
      </DetailRow>

      {/* Version history (only shown when versions exist) */}
      {fileMeta?.versions && fileMeta.versions.length > 0 && folderKey && (
        <VersionHistory
          versions={fileMeta.versions}
          fileName={item.name}
          folderKey={folderKey}
          parentFolderId={parentFolderId}
          fileId={item.ipnsName}
          onRestored={onVersionAction}
        />
      )}
    </div>
  );
}
