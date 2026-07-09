import { useState, useCallback, useEffect, useRef } from 'react';
import type { SealedChildRef } from '@cipherbox/core';
import { Modal } from '../ui/Modal';
import {
  sharesControllerRevokeShare,
  sharesControllerCreateShare,
  sharesControllerGetSentShares,
  sharesControllerUpdateGrant,
} from '@cipherbox/api-client';
import { wrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { useShareStore } from '../../stores/share.store';
import type { SentShare } from '../../stores/share.store';
import { resolveChildNodeIdentity } from '../../lib/crypto/key-wrapping';
import { resolveParentIpnsName } from '../../services/invite.service';
import { getSdkClient } from '../../lib/sdk-provider';
import { InviteLinkTab } from './InviteLinkTab';
import '../../styles/share-dialog.css';
import { logger } from '../../lib/logger';

type ShareDialogProps = {
  isOpen: boolean;
  onClose: () => void;
  /** The item to share (node/v3 SealedChildRef). */
  item: SealedChildRef;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
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
 * Parse a grant's `rootGeneration` (numeric string from the DTO) into a number.
 * Fail-closed (V5, T-68-21): a non-numeric/absent value is `undefined`, never
 * coerced to NaN/0 -- mirrors share.service.ts's parseRootGeneration.
 */
function parseRootGeneration(value: string | undefined | null): number | undefined {
  if (value === undefined || value === null || !/^\d+$/.test(value)) return undefined;
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) ? parsed : undefined;
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
      // The API has no server-side ipnsName filter on /shares/sent -- page
      // through the full sent-share list and filter client-side to this item
      // (mirrors share.service.ts's fetchAllSentShares pagination pattern).
      const pageSize = 100;
      let offset = 0;
      const matches: SentShare[] = [];
      let hasMore = true;
      while (hasMore) {
        const result = await sharesControllerGetSentShares({ limit: pageSize, offset });
        for (const s of result.shares) {
          if (s.shareRootIpnsName !== ipnsName) continue;
          matches.push({
            shareId: s.shareId,
            recipientPublicKey: s.recipientPublicKey,
            ipnsName: s.shareRootIpnsName,
            itemName: item.name,
            itemNameEncrypted: s.itemNameEncrypted,
            // Fail-closed: only a present, non-empty encryptedWriteKey grants
            // write. `!== null` alone would mis-map an absent (undefined) ref to
            // 'write'; a truthy check treats null/undefined/empty as read.
            permission: s.encryptedWriteKey ? 'write' : 'read',
            createdAt: s.createdAt,
            encryptedReadKey: s.encryptedReadKey,
            rootGeneration: parseRootGeneration(s.rootGeneration),
            rootNodeId: s.rootNodeId,
          });
        }
        offset += result.shares.length;
        hasMore = offset < result.total && result.shares.length > 0;
      }
      if (!cancelled) setRecipients(matches);
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
  }, [isOpen, ipnsName, item.name]);

  const handleShare = useCallback(async () => {
    setError(null);
    setSuccess(null);

    const trimmed = pubKeyInput.trim();
    if (!trimmed) return;

    setIsSharing(true);

    let recipientPublicKey: Uint8Array | null = null;
    let itemReadKey: Uint8Array | null = null;

    try {
      const hex = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
      if (!/^04[0-9a-fA-F]{128}$/.test(hex)) {
        throw new Error('invalid public key format');
      }
      recipientPublicKey = hexToBytes(hex);

      const identity = await resolveChildNodeIdentity(item, folderKey);
      itemReadKey = identity.readKey;

      const encryptedReadKey = bytesToHex(await wrapKey(itemReadKey, recipientPublicKey));

      // Write grants: resolve the item's OWN writeKey from the owned
      // write-chain (parent writeKey -> WriteChildRef.writeKeySealed) and
      // ECIES-wrap it for the recipient (68.1-18, SHARE-WRITE-KEY). Raw
      // writeKey material never leaves the SDK -- resolveShareEncryptedWriteKey
      // returns only the wrapped hex encrypted key and zeroes its own derived
      // key internally (D-09).
      let encryptedWriteKey: string | undefined;
      if (permission === 'write') {
        const parentIpnsName = resolveParentIpnsName(parentFolderId);
        encryptedWriteKey = await getSdkClient().resolveShareEncryptedWriteKey(
          parentIpnsName,
          item.ipnsName,
          recipientPublicKey
        );
      }

      let itemNameEncrypted: string | undefined;
      try {
        const nameBytes = new TextEncoder().encode(item.name);
        itemNameEncrypted = bytesToHex(await wrapKey(nameBytes, recipientPublicKey));
      } catch (err) {
        logger.warn('[Share] Failed to wrap item name, continuing without it:', err);
      }

      const result = await sharesControllerCreateShare({
        recipientPublicKey: trimmed.startsWith('0x') ? trimmed : `0x${trimmed}`,
        encryptedReadKey,
        encryptedWriteKey,
        rootNodeId: identity.nodeId,
        shareRootIpnsName: item.ipnsName,
        rootGeneration: String(identity.generation),
        itemNameEncrypted,
      });

      const newShare: SentShare = {
        shareId: result.shareId,
        recipientPublicKey: result.recipientPublicKey,
        ipnsName: item.ipnsName,
        itemName: item.name,
        itemNameEncrypted: result.itemNameEncrypted,
        // Fail-closed: treat absent/null/empty encryptedWriteKey as read.
        permission: result.encryptedWriteKey ? 'write' : 'read',
        createdAt: result.createdAt,
        encryptedReadKey: result.encryptedReadKey,
        rootGeneration: parseRootGeneration(result.rootGeneration),
        rootNodeId: result.rootNodeId,
      };
      setRecipients((prev) => [...prev, newShare]);
      useShareStore.getState().addSentShare(newShare);
      setPubKeyInput('');
      // Include the truncated recipient key — pre-v2.0 message contract that
      // sharing-workflow.spec.ts asserts on (68.1-22).
      setSuccess(
        permission === 'write'
          ? `> shared (read-write) with ${truncateKey(result.recipientPublicKey)}`
          : `> shared with ${truncateKey(result.recipientPublicKey)}`
      );
    } catch (err) {
      logger.error('[Share] Share creation failed:', err);
      // Surface the API's error body (NestJS { message } shape) instead of
      // the raw axios "Request failed with status code NNN" text (68.1-29);
      // lowercased to match the dialog's terminal-style copy.
      const responseMessage = (err as { response?: { data?: { message?: string | string[] } } })
        .response?.data?.message;
      const apiMessage = Array.isArray(responseMessage) ? responseMessage[0] : responseMessage;
      const message =
        apiMessage?.toLowerCase() ?? (err instanceof Error ? err.message : 'share failed');
      setError(`> ${message}`);
    } finally {
      setIsSharing(false);
      itemReadKey?.fill(0);
    }
  }, [pubKeyInput, item, folderKey, permission, parentFolderId]);

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
      // Fail-closed (V5): never PATCH with a coerced generation. An undefined
      // rootGeneration means the DTO carried no valid generation — refuse the
      // upgrade rather than send a stale "0".
      if (share.rootGeneration === undefined) {
        setError('> cannot upgrade: share is stale, please reload');
        return;
      }
      setUpgradingId(share.shareId);

      let recipientPublicKey: Uint8Array | null = null;

      try {
        // Upgrading read -> write mints the shared item's own writeKey from
        // the owned write-chain (parent writeKey -> WriteChildRef.writeKeySealed,
        // 68.1-18's resolveShareEncryptedWriteKey) and PATCHes the SAME share row
        // (no revoke/recreate, same shareId) via updateGrant -- the
        // encryptedReadKey/rootGeneration are re-sent unchanged so this call
        // only ever advances the write side.
        const bareHex = share.recipientPublicKey.startsWith('0x')
          ? share.recipientPublicKey.slice(2)
          : share.recipientPublicKey;
        recipientPublicKey = hexToBytes(bareHex);

        const parentIpnsName = resolveParentIpnsName(parentFolderId);
        const encryptedWriteKey = await getSdkClient().resolveShareEncryptedWriteKey(
          parentIpnsName,
          item.ipnsName,
          recipientPublicKey
        );

        await sharesControllerUpdateGrant(share.shareId, {
          encryptedReadKey: share.encryptedReadKey,
          rootGeneration: String(share.rootGeneration),
          encryptedWriteKey,
        });

        setRecipients((prev) =>
          prev.map((r) => (r.shareId === share.shareId ? { ...r, permission: 'write' } : r))
        );
        useShareStore.getState().updateSentSharePermission(share.shareId, 'write');
        setSuccess('> upgraded to read-write');
      } catch (err) {
        logger.error('[Share] Permission upgrade failed:', err);
        setError('> permission upgrade failed, please try again');
      } finally {
        setUpgradingId(null);
        // recipientPublicKey is public key material (not sensitive), but
        // clear the transient buffer reference regardless (D-09 discipline).
        recipientPublicKey?.fill(0);
      }
    },
    [item, parentFolderId]
  );

  const handleDowngradeConfirm = useCallback(async (share: SentShare) => {
    setError(null);
    setSuccess(null);
    // Fail-closed (V5): refuse to downgrade with a coerced generation.
    if (share.rootGeneration === undefined) {
      setError('> cannot downgrade: share is stale, please reload');
      return;
    }
    setDowngradingId(share.shareId);
    setConfirmDowngradeId(null);

    try {
      // Downgrading write -> read clears the share's encryptedWriteKey via
      // the explicit clearEncryptedWriteKey signal (68.1-19) -- the read side
      // (encryptedReadKey/rootGeneration) is re-sent unchanged, same shareId.
      await sharesControllerUpdateGrant(share.shareId, {
        encryptedReadKey: share.encryptedReadKey,
        rootGeneration: String(share.rootGeneration),
        clearEncryptedWriteKey: true,
      });

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
