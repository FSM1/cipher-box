import { useState, useCallback, useEffect, useRef } from 'react';
// TODO(phase 65): ShareDialog share creation deferred — FolderEntry/FilePointer removed
// Behavioral crypto (decryptFolderMetadata, reWrapEncryptedKey, collectChildKeys) stubbed
import type { SealedChildRef } from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import { sharesControllerRevokeShare } from '@cipherbox/api-client';
import { useShareStore } from '../../stores/share.store';
import { updateSharePermission } from '../../services/share.service';
import { InviteLinkTab } from './InviteLinkTab';
import '../../styles/share-dialog.css';
import { logger } from '../../lib/logger';

type ShareDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  /** The item to share (node/v3 SealedChildRef). TODO(phase 65): use for key re-wrapping */
  item: SealedChildRef;
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
      // deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired
      throw new Error('deferred to Phase 68 — descriptor-ref rotation/grant path not yet wired');
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
    // TODO(phase 65): share creation via Node read-chain (SealedChildRef.readKeySealed unwrap
    // + re-wrap for recipient) not yet implemented. The legacy FolderEntry.folderKeyEncrypted /
    // FilePointer.fileMetaIpnsName paths have been removed with the FolderChild → SealedChildRef
    // type migration. Phase 65 will re-implement using Node.writeBody key-wrapping.
    throw new Error('not implemented — phase 65 (share creation via Node write-chain)');
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
    async (_share: SentShare) => {
      // TODO(phase 65): permission upgrade via Node write-chain not yet implemented
      throw new Error('not implemented — phase 65 (permission upgrade via Node write-chain)');
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

  // TODO(phase 63): SealedChildRef has no .type; display name without kind suffix
  const itemDisplayName = `${item.name}/`; // phase-63 stub: treat as folder
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
                        {/* TODO(phase 63): upgrade/downgrade always shown; SealedChildRef has no .type */}
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
