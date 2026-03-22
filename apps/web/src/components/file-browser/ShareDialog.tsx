import { useState, useCallback, useEffect, useRef } from 'react';
import type { FolderChild, FolderEntry, FilePointer } from '@cipherbox/core';
import { decryptFolderMetadata } from '@cipherbox/core';
import { wrapKey, unwrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { Modal } from '../ui/Modal';
import { useAuthStore } from '../../stores/auth.store';
import { useFolderStore } from '../../stores/folder.store';
import {
  sharesControllerCreateShare,
  sharesControllerLookupUser,
  sharesControllerGetSentShares,
  sharesControllerRevokeShare,
} from '@cipherbox/api-client';
import type { CreateShareDtoItemType, ChildKeyDto } from '@cipherbox/api-client';
import { resolveFileMetadata } from '../../services/file-metadata.service';
import { resolveIpnsRecord } from '../../services/ipns.service';
import { fetchFromIpfs } from '../../lib/api/ipfs';
import { useShareStore } from '../../stores/share.store';
import { collectChildKeys, reWrapEncryptedKey } from '../../lib/crypto/key-wrapping';
import { InviteLinkTab } from './InviteLinkTab';
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
  const [activeTab, setActiveTab] = useState<'direct' | 'invite'>('direct');
  const [pubKeyInput, setPubKeyInput] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [isSharing, setIsSharing] = useState(false);
  const [progress, setProgress] = useState<{ current: number; total: number } | null>(null);
  const [recipients, setRecipients] = useState<SentShare[]>([]);
  const [recipientsLoading, setRecipientsLoading] = useState(false);
  const [recipientsFetched, setRecipientsFetched] = useState(false);
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const directTabRef = useRef<HTMLButtonElement>(null);
  const inviteTabRef = useRef<HTMLButtonElement>(null);

  // Fetch existing recipients when dialog opens
  useEffect(() => {
    if (!isOpen) {
      // Reset state on close
      setActiveTab('direct');
      setPubKeyInput('');
      setError(null);
      setSuccess(null);
      setIsSharing(false);
      setProgress(null);
      setConfirmRevokeId(null);
      setRevokingId(null);
      setRecipients([]);
      setRecipientsLoading(false);
      setRecipientsFetched(false);
      return;
    }

    let cancelled = false;
    setRecipientsLoading(true);

    (async () => {
      const pageSize = 100;
      let offset = 0;
      const allShares: SentShare[] = [];

      // Paginate through all sent shares (API max 100 per page)

      while (true) {
        const response = await sharesControllerGetSentShares({ limit: pageSize, offset });
        if (cancelled) return;
        const pageShares = response.shares
          .filter((s) => s.ipnsName === ipnsName)
          .map((s) => ({
            shareId: s.shareId,
            recipientPublicKey: s.recipientPublicKey,
            itemType: s.itemType as 'folder' | 'file',
            ipnsName: s.ipnsName,
            itemName: s.itemName,
            createdAt: String(s.createdAt),
          }));
        allShares.push(...pageShares);
        offset += response.shares.length;
        if (offset >= response.total || response.shares.length === 0) break;
      }

      if (cancelled) return;
      setRecipients(allShares);
    })()
      .catch((err) => {
        if (cancelled) return;
        console.error('Failed to fetch sent shares:', err);
      })
      .finally(() => {
        if (!cancelled) {
          setRecipientsLoading(false);
          setRecipientsFetched(true);
        }
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
      const lookup = await sharesControllerLookupUser({ publicKey: key });
      if (!lookup.exists) {
        setError('user not found');
        setIsSharing(false);
        return;
      }
    } catch {
      setError('lookup failed, please try again');
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

        try {
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

            setProgress({ current: 0, total: 0 });

            childKeys = await collectChildKeys(
              metadata.children,
              itemFolderKey,
              ownerPrivateKey,
              recipientPubKeyBytes,
              (wrapped) => setProgress({ current: wrapped, total: 0 })
            );
          }
        } finally {
          itemFolderKey.fill(0);
        }
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

      // Update local recipients list and global store (for re-wrapping cache)
      const newShare = {
        shareId: result.shareId,
        recipientPublicKey: key,
        itemType: item.type as 'folder' | 'file',
        ipnsName,
        itemName: item.name,
        createdAt: new Date().toISOString(),
      };
      setRecipients((prev) => [...prev, newShare]);
      useShareStore.getState().addSentShare(newShare);

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
      useShareStore.getState().removeSentShare(shareId);
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
    <Modal open={isOpen} onClose={onClose} title={title} className="share-dialog-backdrop">
      <div className="share-dialog">
        {/* Tab bar */}
        <div className="share-tab-bar" role="tablist" aria-label="Share method">
          <button
            ref={directTabRef}
            type="button"
            role="tab"
            id="share-tab-direct"
            aria-selected={activeTab === 'direct'}
            aria-controls="share-panel-direct"
            tabIndex={activeTab === 'direct' ? 0 : -1}
            className={`share-tab${activeTab === 'direct' ? ' share-tab--active' : ''}`}
            onClick={() => setActiveTab('direct')}
            onKeyDown={(e) => {
              if (e.key === 'ArrowRight') {
                e.preventDefault();
                setActiveTab('invite');
                inviteTabRef.current?.focus();
              }
            }}
          >
            {'DIRECT SHARE'}
          </button>
          <button
            ref={inviteTabRef}
            type="button"
            role="tab"
            id="share-tab-invite"
            aria-selected={activeTab === 'invite'}
            aria-controls="share-panel-invite"
            tabIndex={activeTab === 'invite' ? 0 : -1}
            className={`share-tab${activeTab === 'invite' ? ' share-tab--active' : ''}`}
            onClick={() => setActiveTab('invite')}
            onKeyDown={(e) => {
              if (e.key === 'ArrowLeft') {
                e.preventDefault();
                setActiveTab('direct');
                directTabRef.current?.focus();
              }
            }}
          >
            {'INVITE LINK'}
          </button>
        </div>

        {/* Direct Share tab panel */}
        {activeTab === 'direct' && (
          <div role="tabpanel" id="share-panel-direct" aria-labelledby="share-tab-direct">
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
                  {'> '}re-wrapping keys... {progress.current}
                </div>
              )}
            </div>

            {/* Recipients section */}
            <div className="share-recipients-section">
              <div className="share-recipients-header">{'// recipients'}</div>

              {recipientsLoading || !recipientsFetched ? (
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
        )}

        {/* Invite Link tab panel */}
        {activeTab === 'invite' && (
          <InviteLinkTab
            item={item}
            folderKey={folderKey}
            ipnsName={ipnsName}
            parentFolderId={parentFolderId}
            isOpen={isOpen && activeTab === 'invite'}
          />
        )}
      </div>
    </Modal>
  );
}
