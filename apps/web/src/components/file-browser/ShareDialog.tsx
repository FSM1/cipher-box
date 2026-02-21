import { useState, useCallback, useEffect, useRef } from 'react';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/crypto';
import {
  wrapKey,
  unwrapKey,
  hexToBytes,
  bytesToHex,
  decryptFolderMetadata,
} from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolderStore } from '../../stores/folder.store';
import {
  sharesControllerCreateShare,
  sharesControllerLookupUser,
  sharesControllerGetSentShares,
  sharesControllerRevokeShare,
} from '../../api/shares/shares';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchFromIpfs } from '../../lib/api/ipfs';
import type { CreateShareDtoItemType } from '../../api/models/createShareDtoItemType';
import type { ChildKeyDto } from '../../api/models/childKeyDto';
import '../../styles/share-dialog.css';

type ShareDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  item: FolderChild;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
};

/** Sent share record from the API */
type SentShare = {
  shareId: string;
  recipientPublicKey: string;
  itemType: string;
  ipnsName: string;
  itemName: string;
  createdAt: string;
};

/**
 * Validate public key format: must be 0x04 prefix + 128 hex chars (64 bytes body = 65 bytes total uncompressed).
 */
function isValidPublicKey(key: string): boolean {
  if (!key.startsWith('0x04')) return false;
  // 0x + 130 hex chars = 65 bytes uncompressed secp256k1
  const hexPart = key.slice(2);
  if (hexPart.length !== 130) return false;
  return /^[0-9a-fA-F]+$/.test(hexPart);
}

/**
 * Truncate a public key for display: 0x{first4}...{last4}
 */
function truncateKey(key: string): string {
  if (key.length < 12) return key;
  const hex = key.startsWith('0x') ? key.slice(2) : key;
  return `0x${hex.slice(0, 4)}...${hex.slice(-4)}`;
}

/**
 * Collect all descendant keys from a folder for sharing.
 * Traverses subfolders depth-first, re-wrapping each file and subfolder key
 * for the recipient.
 *
 * @param children - Children of the current folder
 * @param folderKey - Decrypted AES key of the current folder (for resolving file metadata)
 * @param ownerPrivateKey - Owner's secp256k1 private key for unwrapping ECIES keys
 * @param recipientPubKeyBytes - Recipient's uncompressed secp256k1 public key
 * @param onProgress - Callback for progress tracking
 */
async function collectChildKeys(
  children: FolderChild[],
  folderKey: Uint8Array,
  ownerPrivateKey: Uint8Array,
  recipientPubKeyBytes: Uint8Array,
  onProgress: (wrapped: number) => void
): Promise<ChildKeyDto[]> {
  const childKeys: ChildKeyDto[] = [];
  let wrapped = 0;

  for (const child of children) {
    if (child.type === 'file') {
      const fp = child as FilePointer;
      // Resolve file metadata to get fileKeyEncrypted, then re-wrap for recipient
      try {
        const { metadata: fileMeta } = await resolveFileMetadata(fp.fileMetaIpnsName, folderKey);
        const reWrappedFileKey = await reWrapEncryptedKey(
          fileMeta.fileKeyEncrypted,
          ownerPrivateKey,
          recipientPubKeyBytes
        );
        childKeys.push({
          keyType: 'file' as ChildKeyDto['keyType'],
          itemId: fp.id,
          encryptedKey: reWrappedFileKey,
        });
        wrapped++;
        onProgress(wrapped);
      } catch (err) {
        console.error(`Failed to re-wrap file key for ${fp.name}:`, err);
        // Continue with other children
      }
    } else {
      const folder = child as FolderEntry;
      // Re-wrap the subfolder's folderKey for the recipient
      const folderKeyRewrapped = await reWrapEncryptedKey(
        folder.folderKeyEncrypted,
        ownerPrivateKey,
        recipientPubKeyBytes
      );
      childKeys.push({
        keyType: 'folder' as ChildKeyDto['keyType'],
        itemId: folder.id,
        encryptedKey: folderKeyRewrapped,
      });
      wrapped++;
      onProgress(wrapped);

      // Recurse into subfolder: resolve its metadata and collect its children
      try {
        const resolved = await resolveIpnsRecord(folder.ipnsName);
        if (resolved) {
          const folderKeyBytes = await unwrapKey(
            hexToBytes(folder.folderKeyEncrypted),
            ownerPrivateKey
          );
          try {
            const encryptedBytes = await fetchFromIpfs(resolved.cid);
            const encryptedJson = new TextDecoder().decode(encryptedBytes);
            const encrypted = JSON.parse(encryptedJson);
            const metadata = await decryptFolderMetadata(encrypted, folderKeyBytes);

            const subKeys = await collectChildKeys(
              metadata.children,
              folderKeyBytes,
              ownerPrivateKey,
              recipientPubKeyBytes,
              (subWrapped) => {
                onProgress(wrapped + subWrapped);
              }
            );
            wrapped += subKeys.length;
            childKeys.push(...subKeys);
          } finally {
            folderKeyBytes.fill(0);
          }
        }
      } catch (err) {
        console.error(`Failed to traverse subfolder ${folder.name}:`, err);
        // Continue with other children
      }
    }
  }

  return childKeys;
}

/**
 * Re-wrap an ECIES-encrypted hex key from owner to recipient.
 */
async function reWrapEncryptedKey(
  encryptedKeyHex: string,
  ownerPrivateKey: Uint8Array,
  recipientPubKey: Uint8Array
): Promise<string> {
  const plainKey = await unwrapKey(hexToBytes(encryptedKeyHex), ownerPrivateKey);
  const rewrapped = await wrapKey(plainKey, recipientPubKey);
  plainKey.fill(0);
  return bytesToHex(rewrapped);
}

/**
 * Count total items in a folder for progress tracking.
 * Includes both files and subfolders since all need key re-wrapping.
 */
function countFolderChildren(children: FolderChild[]): number {
  return children.length;
}

/**
 * Share dialog modal for creating and managing shares.
 *
 * Allows users to:
 * - Paste a recipient's public key and create a share
 * - View existing recipients with truncated pubkeys
 * - Revoke individual recipients with inline confirm
 *
 * For folders, traverses all descendants and re-wraps keys.
 * For files, wraps the single file key for the recipient.
 */
export function ShareDialog({
  isOpen,
  onClose,
  item,
  folderKey,
  ipnsName,
  parentFolderId,
}: ShareDialogProps) {
  const [pubKeyInput, setPubKeyInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isSharing, setIsSharing] = useState(false);
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null);
  const [recipients, setRecipients] = useState<SentShare[]>([]);
  const [recipientsLoading, setRecipientsLoading] = useState(false);
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);

  // Fetch existing recipients when dialog opens
  useEffect(() => {
    if (!isOpen) {
      // Reset state on close
      setPubKeyInput('');
      setError(null);
      setSuccess(null);
      setIsSharing(false);
      setProgress(null);
      setConfirmRevokeId(null);
      setRevokingId(null);
      return;
    }

    let cancelled = false;
    setRecipientsLoading(true);

    sharesControllerGetSentShares()
      .then((shares) => {
        if (cancelled) return;
        // Filter to shares for this specific item (by ipnsName)
        const itemShares: SentShare[] = shares
          .filter((s) => s.ipnsName === ipnsName)
          .map((s) => ({
            shareId: s.shareId,
            recipientPublicKey: s.recipientPublicKey,
            itemType: s.itemType as 'folder' | 'file',
            ipnsName: s.ipnsName,
            itemName: s.itemName,
            createdAt: String(s.createdAt),
          }));
        setRecipients(itemShares);
      })
      .catch((err) => {
        if (cancelled) return;
        console.error('Failed to fetch sent shares:', err);
      })
      .finally(() => {
        if (!cancelled) setRecipientsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [isOpen, ipnsName]);

  const handleShare = useCallback(async () => {
    setError(null);
    setSuccess(null);

    const key = pubKeyInput.trim();

    // Validate format
    if (!isValidPublicKey(key)) {
      setError('invalid key format -- expected 0x04 + 128 hex chars');
      return;
    }

    // Prevent sharing root folder
    if (parentFolderId === 'root' && item.type === 'folder') {
      // Check if item is the root folder itself (the one navigated to at root)
      const rootFolder = useFolderStore.getState().folders['root'];
      if (rootFolder && item.id === 'root') {
        setError('cannot share root folder');
        return;
      }
    }

    // Check not sharing with yourself
    const vaultKeypair = useAuthStore.getState().vaultKeypair;
    if (!vaultKeypair) {
      setError('vault keypair not available');
      return;
    }

    const myPubKeyHex = '0x' + bytesToHex(vaultKeypair.publicKey);
    if (key.toLowerCase() === myPubKeyHex.toLowerCase()) {
      setError('cannot share with yourself');
      return;
    }

    setIsSharing(true);

    try {
      // Verify recipient is a registered user
      await sharesControllerLookupUser({ publicKey: key });
    } catch {
      setError('user not found');
      setIsSharing(false);
      return;
    }

    try {
      const recipientPubKeyBytes = hexToBytes(key.slice(2));
      const ownerPrivateKey = vaultKeypair.privateKey;

      let encryptedKey: string;
      let childKeys: ChildKeyDto[] | undefined;

      if (item.type === 'folder') {
        const folderEntry = item as FolderEntry;

        // For folders shared from a parent, folderKey IS the folder's own key
        // (it's the folderKey passed as prop which is the parent's key --
        //  but the item is a FolderEntry child that has folderKeyEncrypted)
        // We need to use folderKeyEncrypted from the FolderEntry to get the actual folder key.
        // Wait -- the folderKey prop is the PARENT folder's key. The item's own key
        // is obtained by unwrapping folderKeyEncrypted from the FolderEntry.
        // Actually, looking at the plan more carefully:
        //   "For folders: folderKey is passed as prop"
        // But folderKey is the PARENT's key. For sharing a subfolder, we need the subfolder's key.
        // Let's check: if the item is a direct child folder, its folderKeyEncrypted
        // is wrapped with the owner's public key (ECIES). We unwrap it to get the folder's own key.

        // Unwrap the folder's own key from its encrypted form
        const itemFolderKey = await unwrapKey(
          hexToBytes(folderEntry.folderKeyEncrypted),
          ownerPrivateKey
        );

        // Wrap the folder key for the recipient
        const wrappedForRecipient = await wrapKey(itemFolderKey, recipientPubKeyBytes);
        encryptedKey = bytesToHex(wrappedForRecipient);

        // Now traverse children and re-wrap descendant keys
        // First, resolve folder metadata to get children
        const resolved = await resolveIpnsRecord(folderEntry.ipnsName);
        if (resolved) {
          const encryptedBytes = await fetchFromIpfs(resolved.cid);
          const encryptedJson = new TextDecoder().decode(encryptedBytes);
          const encrypted = JSON.parse(encryptedJson);
          const metadata = await decryptFolderMetadata(encrypted, itemFolderKey);

          const totalSubfolders = countFolderChildren(metadata.children);
          setProgress({ current: 0, total: totalSubfolders });

          childKeys = await collectChildKeys(
            metadata.children,
            itemFolderKey,
            ownerPrivateKey,
            recipientPubKeyBytes,
            (wrapped) => setProgress({ current: wrapped, total: totalSubfolders })
          );
        }

        // Zero the folder key
        itemFolderKey.fill(0);
      } else {
        // File sharing: wrap parent folder key for recipient (needed to decrypt file metadata),
        // and re-wrap the file key as a child key entry
        const filePointer = item as FilePointer;

        // encryptedKey = parent folder key wrapped for recipient
        const wrappedFolderKey = await wrapKey(folderKey, recipientPubKeyBytes);
        encryptedKey = bytesToHex(wrappedFolderKey);

        // Re-wrap the file key for the recipient and store as child key
        const { metadata: fileMeta } = await resolveFileMetadata(
          filePointer.fileMetaIpnsName,
          folderKey
        );
        const reWrappedFileKey = await reWrapEncryptedKey(
          fileMeta.fileKeyEncrypted,
          ownerPrivateKey,
          recipientPubKeyBytes
        );
        childKeys = [
          { keyType: 'file' as const, itemId: filePointer.id, encryptedKey: reWrappedFileKey },
        ];
      }

      // Create the share via API
      const itemType: CreateShareDtoItemType = item.type === 'folder' ? 'folder' : 'file';
      const result = await sharesControllerCreateShare({
        recipientPublicKey: key,
        itemType,
        ipnsName,
        itemName: item.name,
        encryptedKey,
        childKeys: childKeys && childKeys.length > 0 ? childKeys : undefined,
      });

      // Update recipients list
      setRecipients((prev) => [
        ...prev,
        {
          shareId: result.shareId,
          recipientPublicKey: key,
          itemType: item.type,
          ipnsName,
          itemName: item.name,
          createdAt: new Date().toISOString(),
        },
      ]);

      setSuccess(`shared with ${truncateKey(key)}`);
      setPubKeyInput('');
      setProgress(null);
    } catch (err) {
      console.error('Share creation failed:', err);
      const message = err instanceof Error ? err.message : 'share creation failed';
      setError(message);
    } finally {
      setIsSharing(false);
      setProgress(null);
    }
  }, [pubKeyInput, item, folderKey, ipnsName, parentFolderId]);

  const handleRevoke = useCallback(async (shareId: string) => {
    setRevokingId(shareId);
    setConfirmRevokeId(null);
    try {
      await sharesControllerRevokeShare(shareId);
      setRecipients((prev) => prev.filter((r) => r.shareId !== shareId));
    } catch (err) {
      console.error('Revoke failed:', err);
      setError('revoke failed');
    } finally {
      setRevokingId(null);
    }
  }, []);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Enter' && !isSharing) {
        handleShare();
      }
    },
    [handleShare, isSharing]
  );

  const itemDisplayName = item.type === 'folder' ? `${item.name}/` : item.name;
  const title = `SHARE: ${itemDisplayName}`;

  return (
    <Modal open={isOpen} onClose={onClose} title={title}>
      <div className="share-dialog">
        {/* Input section */}
        <div className="share-input-section">
          <label className="share-input-label" htmlFor="share-pubkey-input">
            {'// paste recipient public key'}
          </label>
          <div className="share-input-row">
            <input
              ref={inputRef}
              id="share-pubkey-input"
              type="text"
              className={`share-input${error ? ' share-input--error' : ''}`}
              placeholder="0x04..."
              value={pubKeyInput}
              onChange={(e) => {
                setPubKeyInput(e.target.value);
                setError(null);
                setSuccess(null);
              }}
              onKeyDown={handleKeyDown}
              disabled={isSharing}
              autoComplete="off"
              spellCheck={false}
            />
            <button
              type="button"
              className="share-submit-btn"
              onClick={handleShare}
              disabled={isSharing || !pubKeyInput.trim()}
            >
              {isSharing ? '...' : '--share'}
            </button>
          </div>

          {/* Error message */}
          {error && (
            <div className="share-error" role="alert">
              {'> '}
              {error}
            </div>
          )}

          {/* Success message */}
          {success && (
            <div className="share-success" role="status">
              {'> '}
              {success}
            </div>
          )}

          {/* Progress indicator for folder sharing */}
          {progress && (
            <div className="share-progress" role="status" aria-live="polite">
              {'> '}re-wrapping keys... {progress.current}/{progress.total}
              <div className="share-progress-bar">
                <div
                  className="share-progress-fill"
                  style={{
                    width:
                      progress.total > 0 ? `${(progress.current / progress.total) * 100}%` : '0%',
                  }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Recipients section */}
        <div className="share-recipients-section">
          <div className="share-recipients-header">{'// recipients'}</div>

          {recipientsLoading ? (
            <div className="share-recipients-loading">loading...</div>
          ) : recipients.length === 0 ? (
            <div className="share-recipients-empty">no recipients yet</div>
          ) : (
            <div className="share-recipients-list">
              {recipients.map((recipient) => (
                <div key={recipient.shareId} className="share-recipient">
                  <span className="share-recipient-key">
                    {truncateKey(recipient.recipientPublicKey)}
                  </span>

                  {confirmRevokeId === recipient.shareId ? (
                    <div className="share-revoke-confirm">
                      <span className="share-revoke-confirm-text">{'confirm?'}</span>
                      <button
                        type="button"
                        className="share-revoke-confirm-btn share-revoke-confirm-btn--yes"
                        onClick={() => handleRevoke(recipient.shareId)}
                        disabled={revokingId === recipient.shareId}
                        aria-label="Confirm revoke"
                      >
                        {revokingId === recipient.shareId ? '...' : '[y]'}
                      </button>
                      <button
                        type="button"
                        className="share-revoke-confirm-btn share-revoke-confirm-btn--no"
                        onClick={() => setConfirmRevokeId(null)}
                        aria-label="Cancel revoke"
                      >
                        [n]
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="share-revoke-btn"
                      onClick={() => setConfirmRevokeId(recipient.shareId)}
                      disabled={revokingId !== null}
                      aria-label={`Revoke share for ${truncateKey(recipient.recipientPublicKey)}`}
                    >
                      --revoke
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
}
