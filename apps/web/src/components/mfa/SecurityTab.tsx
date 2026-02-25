import { useCallback, useEffect, useState } from 'react';
import { useMfa } from '../../hooks/useMfa';
import { useAuth } from '../../hooks/useAuth';
import { authApi } from '../../lib/api/auth';
import { MfaEnrollmentWizard } from './MfaEnrollmentWizard';
import { AuthorizedDevices } from './AuthorizedDevices';
import { RecoveryPhraseSection } from './RecoveryPhraseSection';

/**
 * Security tab for the Settings page.
 *
 * Displays MFA status badge, enrollment wizard trigger, authorized devices
 * list, and recovery phrase management. Checks MFA status on mount and
 * after enrollment completes.
 */
export function SecurityTab() {
  const { checkMfaStatus, isMfaEnabled, factorCount, threshold } = useMfa();
  const { logout } = useAuth();
  const [showWizard, setShowWizard] = useState(false);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [deleteInput, setDeleteInput] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  // Check MFA status on mount
  useEffect(() => {
    checkMfaStatus();
  }, [checkMfaStatus]);

  const handleEnrollmentComplete = useCallback(() => {
    setShowWizard(false);
    checkMfaStatus();
  }, [checkMfaStatus]);

  const handleEnrollmentCancel = useCallback(() => {
    setShowWizard(false);
  }, []);

  const handleDeleteAccount = useCallback(async () => {
    if (deleteInput !== 'DELETE') return;
    setIsDeleting(true);
    setDeleteError(null);
    try {
      await authApi.deleteAccount();
      // Account deleted server-side. Clear local state and redirect.
      try {
        await logout();
      } catch {
        // Account is already gone — force redirect even if logout cleanup fails
        window.location.href = '/';
      }
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Failed to delete account');
      setIsDeleting(false);
    }
  }, [deleteInput, logout]);

  const handleCancelDelete = useCallback(() => {
    setShowDeleteConfirm(false);
    setDeleteInput('');
    setDeleteError(null);
  }, []);

  return (
    <div className="security-tab">
      {/* MFA Status Badge */}
      <div className="security-tab-status">
        <span
          className={`security-tab-status-dot ${isMfaEnabled ? 'enabled' : 'disabled'}`}
          aria-hidden="true"
        />
        <span className={`security-tab-status-label ${isMfaEnabled ? 'enabled' : 'disabled'}`}>
          {isMfaEnabled ? '[ENABLED]' : '[DISABLED]'}
        </span>
      </div>

      {/* Factor info when enabled */}
      {isMfaEnabled && factorCount > 0 && (
        <p className="security-tab-factor-info">
          {factorCount} factors active, {threshold}/{factorCount} threshold
        </p>
      )}

      {/* Enrollment wizard or trigger */}
      {showWizard ? (
        <MfaEnrollmentWizard
          onComplete={handleEnrollmentComplete}
          onCancel={handleEnrollmentCancel}
        />
      ) : (
        <>
          {/* Enable MFA section (only when disabled) */}
          {!isMfaEnabled && (
            <div className="security-tab-enable">
              <h3 className="security-tab-enable-title">
                {'// enable multi-factor authentication'}
              </h3>
              <p className="security-tab-enable-desc">
                Protect your vault with an additional layer of security. New devices will require
                approval from an existing device or your recovery phrase.
              </p>
              <button
                type="button"
                className="security-tab-enable-btn"
                onClick={() => setShowWizard(true)}
              >
                --enable-mfa
              </button>
            </div>
          )}

          {/* Authorized Devices section (only when MFA enabled) */}
          {isMfaEnabled && (
            <div className="security-tab-section">
              <h3 className="security-tab-section-title">{'// authorized devices'}</h3>
              <AuthorizedDevices />
            </div>
          )}

          {/* Recovery Phrase section (only when MFA enabled) */}
          {isMfaEnabled && (
            <div className="security-tab-section">
              <h3 className="security-tab-section-title">{'// recovery phrase'}</h3>
              <RecoveryPhraseSection />
            </div>
          )}
        </>
      )}

      {/* Danger Zone */}
      <div className="security-tab-danger-zone">
        <h3 className="security-tab-danger-zone-title">{'// danger_zone'}</h3>
        {!showDeleteConfirm ? (
          <div className="security-tab-danger-zone-content">
            <p className="security-tab-danger-zone-desc">
              permanently delete your account and all associated data. this action cannot be undone.
            </p>
            <button
              type="button"
              className="security-tab-danger-btn"
              onClick={() => setShowDeleteConfirm(true)}
            >
              --delete-account
            </button>
          </div>
        ) : (
          <div className="security-tab-danger-zone-confirm">
            <p className="security-tab-danger-zone-warn">
              this will permanently delete your account, vault, files, shares, and all encryption
              keys. type <strong>DELETE</strong> to confirm.
            </p>
            <input
              type="text"
              className="security-tab-danger-input"
              aria-label="Type DELETE to confirm account deletion"
              value={deleteInput}
              onChange={(e) => setDeleteInput(e.target.value)}
              placeholder="type DELETE to confirm"
              autoComplete="off"
              spellCheck={false}
              disabled={isDeleting}
            />
            {deleteError && <p className="security-tab-danger-error">{deleteError}</p>}
            <div className="security-tab-danger-actions">
              <button
                type="button"
                className="security-tab-danger-cancel"
                onClick={handleCancelDelete}
                disabled={isDeleting}
              >
                --cancel
              </button>
              <button
                type="button"
                className="security-tab-danger-confirm-btn"
                onClick={handleDeleteAccount}
                disabled={deleteInput !== 'DELETE' || isDeleting}
              >
                {isDeleting ? 'deleting...' : '--confirm-delete'}
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Desktop note */}
      <p className="security-tab-note">
        {'// '}MFA is available on web only. Desktop support coming soon.
      </p>
    </div>
  );
}
