import { useState, useCallback, useEffect } from 'react';
import type { FolderChild } from '@cipherbox/core';
import { createInviteLink, fetchInvitesForItem, revokeInvite } from '../../services/invite.service';
import type { InviteInfo } from '../../services/invite.service';
import { logger } from '../../lib/logger';

type InviteLinkTabProps = {
  item: FolderChild;
  folderKey: Uint8Array;
  ipnsName: string;
  parentFolderId: string;
  isOpen: boolean;
};

/**
 * Invite Link tab content for the ShareDialog.
 *
 * Allows users to:
 * - Create an invite link (URL auto-copied to clipboard)
 * - View active (unclaimed, unexpired) invite links with metadata
 * - Revoke individual invite links with inline confirm
 *
 * IMPORTANT: The ephemeral private key is NOT stored after creation.
 * The URL is copied to clipboard at creation time only. Existing invites
 * show metadata and revoke action, but NOT a copy action.
 */
export function InviteLinkTab({
  item,
  folderKey,
  ipnsName,
  parentFolderId,
  isOpen,
}: InviteLinkTabProps) {
  const [invites, setInvites] = useState<InviteInfo[]>([]);
  const [invitesLoading, setInvitesLoading] = useState(true);
  const [isCreating, setIsCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const [confirmRevokeId, setConfirmRevokeId] = useState<string | null>(null);
  const [revokingId, setRevokingId] = useState<string | null>(null);

  // Fetch active invites when tab becomes visible
  useEffect(() => {
    if (!isOpen) return;

    let cancelled = false;
    setInvitesLoading(true);
    setInvites([]);
    setError(null);

    fetchInvitesForItem(ipnsName)
      .then((result) => {
        if (!cancelled) {
          setInvites(result);
        }
      })
      .catch((err) => {
        if (!cancelled) {
          logger.error('[Invite] Failed to fetch invites:', err);
          setError('failed to load invite links');
          setInvites([]);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setInvitesLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [isOpen, ipnsName]);

  const handleCreate = useCallback(async () => {
    setError(null);
    setSuccess(null);
    setIsCreating(true);

    try {
      const { url } = await createInviteLink({
        item,
        folderKey,
        ipnsName,
        parentFolderId,
      });

      // Auto-copy URL to clipboard
      let copied = false;
      try {
        await navigator.clipboard.writeText(url);
        copied = true;
      } catch {
        // Clipboard may not be available (e.g., insecure context)
      }

      // Truncate URL for display
      const displayUrl = url.length > 60 ? `${url.slice(0, 30)}...${url.slice(-20)}` : url;
      setSuccess(
        copied
          ? `link copied to clipboard: ${displayUrl}`
          : `link created (copy failed -- save this): ${displayUrl}`
      );

      // Refresh invite list (don't overwrite success on failure)
      try {
        const updatedInvites = await fetchInvitesForItem(ipnsName);
        setInvites(updatedInvites);
      } catch {
        // List refresh failed, but invite was created successfully
      }
    } catch (err) {
      logger.error('[Invite] Failed to create invite link:', err);
      const message = err instanceof Error ? err.message : 'failed to create invite link';
      setError(message);
    } finally {
      setIsCreating(false);
    }
  }, [item, folderKey, ipnsName, parentFolderId]);

  const handleRevoke = useCallback(async (inviteId: string) => {
    setRevokingId(inviteId);
    setConfirmRevokeId(null);
    setError(null);

    try {
      await revokeInvite(inviteId);
      setInvites((prev) => prev.filter((inv) => inv.id !== inviteId));
    } catch (err) {
      logger.error('[Invite] Failed to revoke invite:', err);
      setError('revoke failed');
    } finally {
      setRevokingId(null);
    }
  }, []);

  /**
   * Format a date string for display: "Feb 23, 2026"
   */
  const formatDate = (dateStr: string): string => {
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });
    } catch {
      return dateStr;
    }
  };

  return (
    <div
      className="invite-link-tab"
      role="tabpanel"
      id="share-panel-invite"
      aria-labelledby="share-tab-invite"
    >
      {/* Create invite link button */}
      <div className="invite-link-create">
        <button
          type="button"
          className="invite-link-create-btn"
          onClick={handleCreate}
          disabled={isCreating}
        >
          {isCreating ? 'creating...' : '--create invite link'}
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

      {/* Active invites list */}
      <div className="invite-link-list-section">
        <div className="share-recipients-header">{'// active invite links'}</div>

        {invitesLoading ? (
          <div className="share-recipients-loading">loading...</div>
        ) : invites.length === 0 ? (
          <div className="share-recipients-empty">no active invite links</div>
        ) : (
          <div className="invite-link-list">
            {invites.map((invite) => (
              <div key={invite.id} className="invite-link-item">
                <div className="invite-link-info">
                  <span className="invite-status-badge">ACTIVE</span>
                  <span className="invite-link-meta">
                    {'created '}
                    {formatDate(invite.createdAt)}
                    {' | expires '}
                    {formatDate(invite.expiresAt)}
                  </span>
                </div>

                <div className="invite-link-actions">
                  {confirmRevokeId === invite.id ? (
                    <div className="share-revoke-confirm">
                      <span className="share-revoke-confirm-text">{'confirm?'}</span>
                      <button
                        type="button"
                        className="share-revoke-confirm-btn share-revoke-confirm-btn--yes"
                        onClick={() => handleRevoke(invite.id)}
                        disabled={revokingId === invite.id}
                        aria-label="Confirm revoke invite"
                      >
                        {revokingId === invite.id ? '...' : '[y]'}
                      </button>
                      <button
                        type="button"
                        className="share-revoke-confirm-btn share-revoke-confirm-btn--no"
                        onClick={() => setConfirmRevokeId(null)}
                        aria-label="Cancel revoke invite"
                      >
                        [n]
                      </button>
                    </div>
                  ) : (
                    <button
                      type="button"
                      className="share-revoke-btn"
                      onClick={() => setConfirmRevokeId(invite.id)}
                      disabled={revokingId !== null}
                      aria-label="Revoke invite link"
                    >
                      --revoke
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
