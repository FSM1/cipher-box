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
import { updateSharePermission } from '../../services/share.service';
import { InviteLinkTab } from './InviteLinkTab';
import '../../styles/share-dialog.css';
import { logger } from '../../lib/logger';

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
  permission: 'read' | 'write';
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
  const [permission, setPermission] = useState<'read' | 'write'>('read');
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [confirmDowngradeId, setConfirmDowngradeId] = useState<string | null>(null);
  const [upgradingId, setUpgradingId] = useState<string | null>(null);
  const [downgradingId, setDowngradingId] = useState<string | null>(null);

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
      setPermission('read');
      setConfirmRevokeId(null);
      setRevokingId(null);
      setConfirmDowngradeId(null);
      setUpgradingId(null);
      setDowngradingId(null);
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
            permission: ((s.permission as 'read' | 'write') ?? 'read') as 'read' | 'write',
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
        logger.error('[Share] Failed to fetch sent shares:', err);
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
      let encryptedIpnsKeyHex: string | undefined;

      if (item.type === 'folder') {
        const folderEntry = item as FolderEntry;

        // Unwrap the folder's own key from its ECIES-encrypted form
        const itemFolderKey = await unwrapKey(
          hexToBytes(folderEntry.folderKeyEncrypted),
          ownerPrivateKey
        );

        try {
          // Wrap the folder key for the recipient
          const wrappedForRecipient = await wrapKey(itemFolderKey, recipientPubKeyBytes);
          encryptedKey = bytesToHex(wrappedForRecipient);

          // For write shares, also wrap the IPNS private key for the recipient
          if (permission === 'write') {
            const ipnsPrivKey = await unwrapKey(
              hexToBytes(folderEntry.ipnsPrivateKeyEncrypted),
              ownerPrivateKey
            );
            try {
              const wrappedIpnsKey = await wrapKey(ipnsPrivKey, recipientPubKeyBytes);
              encryptedIpnsKeyHex = bytesToHex(wrappedIpnsKey);
            } finally {
              ipnsPrivKey.fill(0);
            }
          }

          // Traverse children and re-wrap descendant keys
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
              permission,
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

        // For write shares, also wrap the file's IPNS private key for the recipient
        if (permission === 'write' && filePointer.ipnsPrivateKeyEncrypted) {
          const fileIpnsPrivKey = await unwrapKey(
            hexToBytes(filePointer.ipnsPrivateKeyEncrypted),
            ownerPrivateKey
          );
          try {
            const wrappedIpnsKey = await wrapKey(fileIpnsPrivKey, recipientPubKeyBytes);
            encryptedIpnsKeyHex = bytesToHex(wrappedIpnsKey);

            // Also add file-ipns child key so recipient can update file content
            const recipientWrappedIpnsKey = await wrapKey(fileIpnsPrivKey, recipientPubKeyBytes);
            childKeys.push({
              keyType: 'file-ipns' as const,
              itemId: filePointer.id,
              encryptedKey: bytesToHex(recipientWrappedIpnsKey),
            });
          } finally {
            fileIpnsPrivKey.fill(0);
          }
        }
      }

      // Downgrade to read if write was requested but IPNS key is unavailable (legacy files)
      const effectivePermission =
        permission === 'write' && !encryptedIpnsKeyHex ? 'read' : permission;

      // REQ-4: ECIES-wrap the display name for the recipient (mirrors the
      // encryptedKey wrap above). Only ciphertext leaves the browser — the
      // plaintext itemName is NOT sent for new shares (server stores '' + bytea).
      const itemNameBytes = new TextEncoder().encode(item.name);
      let itemNameEncrypted: string;
      try {
        itemNameEncrypted = bytesToHex(await wrapKey(itemNameBytes, recipientPubKeyBytes));
      } finally {
        itemNameBytes.fill(0);
      }

      // Create the share via API
      const itemType: CreateShareDtoItemType = item.type === 'folder' ? 'folder' : 'file';
      const result = await sharesControllerCreateShare({
        recipientPublicKey: key,
        itemType,
        ipnsName,
        itemName: '',
        itemNameEncrypted,
        encryptedKey,
        permission: effectivePermission,
        encryptedIpnsKey: encryptedIpnsKeyHex,
        childKeys: childKeys && childKeys.length > 0 ? childKeys : undefined,
      });

      // Update local recipients list and global store (for re-wrapping cache).
      // The owner keeps the plaintext display name in-memory only (it never
      // leaves the browser); itemNameEncrypted marks the row as already wrapped
      // so the lazy backfill never re-fires on it.
      const newShare = {
        shareId: result.shareId,
        recipientPublicKey: key,
        itemType: item.type as 'folder' | 'file',
        ipnsName,
        itemName: item.name,
        itemNameEncrypted,
        permission: effectivePermission,
        createdAt: new Date().toISOString(),
      };
      setRecipients((prev) => [...prev, newShare]);
      useShareStore.getState().addSentShare(newShare);

      setSuccess(
        effectivePermission === 'write'
          ? `shared (read-write) with ${truncateKey(key)}`
          : `shared with ${truncateKey(key)}`
      );
      setPubKeyInput('');
      setProgress(null);
    } catch (err) {
      logger.error('[Share] Share creation failed:', err);
      const message = err instanceof Error ? err.message : 'share creation failed';
      setError(message);
    } finally {
      setIsSharing(false);
      setProgress(null);
    }
  }, [pubKeyInput, item, folderKey, ipnsName, parentFolderId, permission]);

  const handleRevoke = useCallback(async (shareId: string) => {
    setRevokingId(shareId);
    setConfirmRevokeId(null);
    try {
      await sharesControllerRevokeShare(shareId);
      setRecipients((prev) => prev.filter((r) => r.shareId !== shareId));
      useShareStore.getState().removeSentShare(shareId);
    } catch (err) {
      logger.error('[Share] Revoke failed:', err);
      setError('revoke failed');
    } finally {
      setRevokingId(null);
    }
  }, []);

  const handleUpgrade = useCallback(
    async (share: SentShare) => {
      setError(null);
      setSuccess(null);
      setUpgradingId(share.shareId);

      try {
        // Get vault keypair for unwrapping IPNS key
        const vaultKeypair = useAuthStore.getState().vaultKeypair;
        if (!vaultKeypair) {
          setError('vault keypair not available');
          setUpgradingId(null);
          return;
        }

        const ownerPrivateKey = vaultKeypair.privateKey;
        const recipientPubKeyBytes = hexToBytes(
          share.recipientPublicKey.startsWith('0x')
            ? share.recipientPublicKey.slice(2)
            : share.recipientPublicKey
        );

        // Unwrap IPNS private key and re-wrap for recipient
        const ipnsKeyEncrypted =
          item.type === 'folder'
            ? (item as FolderEntry).ipnsPrivateKeyEncrypted
            : (item as FilePointer).ipnsPrivateKeyEncrypted;

        if (!ipnsKeyEncrypted) {
          setError('IPNS key not available for this item');
          setUpgradingId(null);
          return;
        }

        const ipnsPrivKey = await unwrapKey(hexToBytes(ipnsKeyEncrypted), ownerPrivateKey);
        let encryptedIpnsKeyHex: string;
        try {
          const wrappedIpnsKey = await wrapKey(ipnsPrivKey, recipientPubKeyBytes);
          encryptedIpnsKeyHex = bytesToHex(wrappedIpnsKey);
        } finally {
          ipnsPrivKey.fill(0);
        }

        await updateSharePermission(share.shareId, 'write', encryptedIpnsKeyHex);

        // Update local state
        setRecipients((prev) =>
          prev.map((r) => (r.shareId === share.shareId ? { ...r, permission: 'write' } : r))
        );
        useShareStore.getState().updateSentSharePermission(share.shareId, 'write');
        setSuccess('> upgraded to read-write');
      } catch (err) {
        logger.error('[Share] Permission upgrade failed:', err);
        setError('> permission change failed, please try again');
      } finally {
        setUpgradingId(null);
      }
    },
    [item]
  );

  const handleDowngradeConfirm = useCallback(async (share: SentShare) => {
    setError(null);
    setSuccess(null);
    setDowngradingId(share.shareId);
    setConfirmDowngradeId(null);

    try {
      await updateSharePermission(share.shareId, 'read');

      // Update local state
      setRecipients((prev) =>
        prev.map((r) => (r.shareId === share.shareId ? { ...r, permission: 'read' } : r))
      );
      useShareStore.getState().updateSentSharePermission(share.shareId, 'read');
      setSuccess('> downgraded to read-only');
    } catch (err) {
      logger.error('[Share] Permission downgrade failed:', err);
      setError('> permission change failed, please try again');
    } finally {
      setDowngradingId(null);
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

              {/* Permission toggle */}
              <div className="share-permission-selector">
                <label className="share-permission-label">{'// permission'}</label>
                <div
                  className="share-permission-toggle"
                  role="radiogroup"
                  aria-label="Permission level"
                  onKeyDown={(e) => {
                    if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                      e.preventDefault();
                      setPermission((prev) => (prev === 'read' ? 'write' : 'read'));
                    }
                  }}
                >
                  <button
                    type="button"
                    role="radio"
                    aria-checked={permission === 'read'}
                    tabIndex={permission === 'read' ? 0 : -1}
                    className={`share-perm-btn${permission === 'read' ? ' share-perm-btn--active' : ''}`}
                    onClick={() => setPermission('read')}
                  >
                    {'[ READ-ONLY ]'}
                  </button>
                  <button
                    type="button"
                    role="radio"
                    aria-checked={permission === 'write'}
                    tabIndex={permission === 'write' ? 0 : -1}
                    className={`share-perm-btn${permission === 'write' ? ' share-perm-btn--active' : ''}`}
                    onClick={() => setPermission('write')}
                  >
                    {'[ READ-WRITE ]'}
                  </button>
                </div>
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
                      <span
                        className={
                          recipient.permission === 'write'
                            ? 'recipient-perm-write'
                            : 'recipient-perm-read'
                        }
                      >
                        {recipient.permission === 'write' ? '[write]' : '[read]'}
                      </span>

                      <div className="share-recipient-actions">
                        {/* Upgrade/downgrade controls (folders only) */}
                        {item.type === 'folder' && (
                          <>
                            {recipient.permission === 'read' ? (
                              <button
                                type="button"
                                className="share-action-btn share-upgrade-btn"
                                onClick={() => handleUpgrade(recipient)}
                                disabled={
                                  upgradingId !== null ||
                                  downgradingId !== null ||
                                  revokingId !== null
                                }
                                aria-label={`Upgrade ${truncateKey(recipient.recipientPublicKey)} to read-write`}
                              >
                                {upgradingId === recipient.shareId ? '...' : '--upgrade'}
                              </button>
                            ) : confirmDowngradeId === recipient.shareId ? (
                              <div className="share-revoke-confirm">
                                <span className="share-revoke-confirm-text">{'confirm?'}</span>
                                <button
                                  type="button"
                                  className="share-revoke-confirm-btn share-revoke-confirm-btn--yes"
                                  onClick={() => handleDowngradeConfirm(recipient)}
                                  disabled={downgradingId === recipient.shareId}
                                  aria-label="Confirm downgrade"
                                >
                                  {downgradingId === recipient.shareId ? '...' : '[y]'}
                                </button>
                                <button
                                  type="button"
                                  className="share-revoke-confirm-btn share-revoke-confirm-btn--no"
                                  onClick={() => setConfirmDowngradeId(null)}
                                  aria-label="Cancel downgrade"
                                >
                                  {'[n]'}
                                </button>
                              </div>
                            ) : (
                              <button
                                type="button"
                                className="share-action-btn share-downgrade-btn"
                                onClick={() => setConfirmDowngradeId(recipient.shareId)}
                                disabled={
                                  upgradingId !== null ||
                                  downgradingId !== null ||
                                  revokingId !== null
                                }
                                aria-label={`Downgrade ${truncateKey(recipient.recipientPublicKey)} to read-only`}
                              >
                                {'--downgrade'}
                              </button>
                            )}
                          </>
                        )}

                        {/* Revoke button */}
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
                              {'[n]'}
                            </button>
                          </div>
                        ) : (
                          <button
                            type="button"
                            className="share-revoke-btn"
                            onClick={() => setConfirmRevokeId(recipient.shareId)}
                            disabled={
                              revokingId !== null || upgradingId !== null || downgradingId !== null
                            }
                            aria-label={`Revoke share for ${truncateKey(recipient.recipientPublicKey)}`}
                          >
                            {'--revoke'}
                          </button>
                        )}
                      </div>
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
