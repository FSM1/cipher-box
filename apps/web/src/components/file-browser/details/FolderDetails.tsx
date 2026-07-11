import type { ResolvedChild } from '@cipherbox/sdk';
import { deriveDeviceId } from '@cipherbox/crypto';
import { formatDate } from '../../../utils/format';
import { CopyableValue, DetailRow } from './DetailsPrimitives';

/**
 * Folder details content (node/v3: ResolvedChild display).
 *
 * The ResolvedChild is already resolved via the SDK read chain, so its display
 * metadata (name/kind/createdAt/modifiedAt) is available directly.
 */
/**
 * Render a NON-reversible fingerprint of a key: a short prefix of its SHA-256
 * hex digest. The digest is one-way, so — unlike the prior raw-hex slice — this
 * leaks zero key material into the DOM. (`deriveDeviceId` = SHA-256(bytes) hex.)
 */
function keyFingerprint(key: Uint8Array): string {
  return `sha256:${deriveDeviceId(key).slice(0, 16)}`;
}

export function FolderDetails({
  item,
  metadataCid,
  metadataLoading,
  sequenceNumber,
  childCount,
  folderKey,
  ipnsPrivateKey,
  readKeySealed,
}: {
  item: ResolvedChild;
  metadataCid: string | null;
  metadataLoading: boolean;
  sequenceNumber: bigint | null;
  childCount: number | null;
  /** Decrypted folder read key, if this folder is loaded in the SDK's folderTree. */
  folderKey: Uint8Array | null;
  /** Decrypted IPNS signing private key, if this folder is loaded in the SDK's folderTree. */
  ipnsPrivateKey: Uint8Array | null;
  /**
   * The folder's AES-GCM sealed readKey blob, as it lives in the PARENT
   * folder's `SealedChildRef.readKeySealed` (not present on `ResolvedChild` --
   * this is a write/crypto-identity field, not a display field, so the caller
   * threads it through separately).
   */
  readKeySealed: string;
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
        <span className="details-value details-value--redacted">
          {readKeySealed.slice(0, 16)}...{readKeySealed.slice(-8)} (sealed under parent read-key)
        </span>
      </DetailRow>

      <DetailRow label="Folder Key">
        {folderKey ? (
          <span className="details-value details-value--redacted">{keyFingerprint(folderKey)}</span>
        ) : (
          <span className="details-value details-value--dim">unavailable (not loaded)</span>
        )}
      </DetailRow>

      <DetailRow label="IPNS Private Key">
        {ipnsPrivateKey ? (
          <span className="details-value details-value--redacted">
            {keyFingerprint(ipnsPrivateKey)}
          </span>
        ) : (
          <span className="details-value details-value--dim">unavailable (not loaded)</span>
        )}
      </DetailRow>

      {/* Timestamps */}
      <div className="details-section-header">{'// timestamps'}</div>

      <DetailRow label="Created">
        {typeof item.createdAt === 'number' && Number.isFinite(item.createdAt) ? (
          <span className="details-value">{formatDate(item.createdAt)}</span>
        ) : (
          <span className="details-value details-value--dim">—</span>
        )}
      </DetailRow>

      <DetailRow label="Modified">
        {typeof item.modifiedAt === 'number' && Number.isFinite(item.modifiedAt) ? (
          <span className="details-value">{formatDate(item.modifiedAt)}</span>
        ) : (
          <span className="details-value details-value--dim">—</span>
        )}
      </DetailRow>
    </div>
  );
}
