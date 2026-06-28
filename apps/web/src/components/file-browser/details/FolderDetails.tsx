import type { SealedChildRef } from '@cipherbox/core';
import { CopyableValue, DetailRow } from './DetailsPrimitives';

/**
 * Folder details content (node/v3: SealedChildRef display).
 * TODO(phase 63): wire read-chain navigation to load Node for full metadata.
 */
export function FolderDetails({
  item,
  metadataCid,
  metadataLoading,
  sequenceNumber,
  childCount,
}: {
  item: SealedChildRef;
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

      <DetailRow label="Read Key Sealed">
        {/* TODO(phase 63): readKeySealed is an AES-GCM sealed blob inside the parent's read-body */}
        <span className="details-value details-value--redacted">
          {item.readKeySealed.slice(0, 16)}...{item.readKeySealed.slice(-8)} (sealed under parent
          read-key)
        </span>
      </DetailRow>

      {/* Timestamps */}
      <div className="details-section-header">{'// timestamps'}</div>

      <DetailRow label="Created">
        {/* TODO(phase 63): SealedChildRef has no createdAt; resolve from Node envelope */}
        <span className="details-value details-value--dim">unavailable (phase 63)</span>
      </DetailRow>

      <DetailRow label="Modified">
        {/* TODO(phase 63): SealedChildRef has no modifiedAt; resolve from Node envelope */}
        <span className="details-value details-value--dim">unavailable (phase 63)</span>
      </DetailRow>
    </div>
  );
}
