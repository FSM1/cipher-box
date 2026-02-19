import { useCallback, useEffect, useState } from 'react';
import { useMfa } from '../../hooks/useMfa';
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
  const [showWizard, setShowWizard] = useState(false);

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

      {/* Desktop note */}
      <p className="security-tab-note">
        {'// '}MFA is available on web only. Desktop support coming soon.
      </p>
    </div>
  );
}
