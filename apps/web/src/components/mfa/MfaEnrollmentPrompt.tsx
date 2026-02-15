import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';
import { useMfa } from '../../hooks/useMfa';
import { useMfaStore } from '../../stores/mfa.store';
import { useAuthStore } from '../../stores/auth.store';

const STORAGE_KEY_PREFIX = 'cipherbox_mfa_prompt_dismissed_';

/**
 * Get the localStorage key for dismissal persistence.
 * Uses userEmail when available, falls back to 'default'.
 */
function getDismissalKey(): string {
  const email = useAuthStore.getState().userEmail;
  return `${STORAGE_KEY_PREFIX}${email || 'default'}`;
}

/**
 * Dismissable banner shown after login for non-MFA users.
 * Nudges users to set up MFA from Settings > Security.
 *
 * Visibility rules:
 * - Only shows when authenticated AND MFA is not enabled
 * - Respects in-memory dismissal (mfa.store hasSeenPrompt)
 * - Respects cross-session dismissal (localStorage keyed by user)
 * - Shows once per session (first render after login)
 *
 * Mounted in AppShell above the main content area.
 */
export function MfaEnrollmentPrompt() {
  const navigate = useNavigate();
  const { isAuthenticated } = useAuth();
  const { checkMfaStatus, isMfaEnabled } = useMfa();
  const hasSeenPrompt = useMfaStore((s) => s.hasSeenPrompt);
  const dismissPrompt = useMfaStore((s) => s.dismissPrompt);

  const [visible, setVisible] = useState(false);
  const checkedRef = useRef(false);

  // Check MFA status on mount and determine visibility
  useEffect(() => {
    if (!isAuthenticated || checkedRef.current) return;
    checkedRef.current = true;

    const { isMfaEnabled: enabled } = checkMfaStatus();
    if (enabled) return;

    // Check in-memory dismissal
    if (hasSeenPrompt) return;

    // Check localStorage for cross-session dismissal
    try {
      if (localStorage.getItem(getDismissalKey()) === 'true') return;
    } catch {
      // localStorage unavailable (incognito, etc.)
    }

    setVisible(true);
  }, [isAuthenticated, checkMfaStatus, hasSeenPrompt]);

  const handleDismiss = useCallback(() => {
    setVisible(false);
    dismissPrompt();

    // Persist dismissal in localStorage
    try {
      localStorage.setItem(getDismissalKey(), 'true');
    } catch {
      // localStorage unavailable
    }
  }, [dismissPrompt]);

  const handleSetupMfa = useCallback(() => {
    handleDismiss();
    navigate('/settings?tab=security');
  }, [handleDismiss, navigate]);

  // Don't render if not visible or MFA already enabled
  if (!visible || !isAuthenticated || isMfaEnabled) return null;

  return (
    <div className="mfa-prompt" role="banner">
      <span className="mfa-prompt-text">
        <strong>{'// secure your account'}</strong>
        {' -- enable MFA to protect your vault on new devices.'}
      </span>
      <button
        type="button"
        className="mfa-prompt-btn mfa-prompt-btn-setup"
        onClick={handleSetupMfa}
      >
        --setup-mfa
      </button>
      <button
        type="button"
        className="mfa-prompt-dismiss"
        onClick={handleDismiss}
        aria-label="Dismiss MFA prompt"
      >
        [x]
      </button>
    </div>
  );
}
