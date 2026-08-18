import { useState } from 'react';
import { LogoutButton } from '../auth/LogoutButton';
import { RecoveryPhraseSetup } from '../auth/RecoveryPhraseSetup';
import { useAuth } from '../../auth/useAuth';
import { useAuthState } from '../../stores/auth.store';

/**
 * Who is signed in, and the way out. Escape is handled on the container, not the
 * trigger, so it still closes once focus moves into the dropdown.
 */
export function UserMenu() {
  const { email } = useAuthState();
  const { recoveryEnrolled } = useAuth();
  const [isOpen, setIsOpen] = useState(false);
  const [settingUpRecovery, setSettingUpRecovery] = useState(false);

  return (
    <div
      className="user-menu"
      data-testid="user-menu"
      onMouseEnter={() => setIsOpen(true)}
      onMouseLeave={() => setIsOpen(false)}
      onKeyDown={(event) => {
        if (event.key === 'Escape') setIsOpen(false);
      }}
    >
      <button
        className="user-menu-trigger"
        type="button"
        aria-expanded={isOpen}
        aria-haspopup="true"
        onClick={() => setIsOpen(!isOpen)}
      >
        {/* Wallet logins carry no email. */}
        <span className="user-menu-email">{email ?? '[an0n]'}</span>
        <span className="user-menu-caret">&#9660;</span>
      </button>

      {isOpen && (
        <div className="user-menu-dropdown" role="menu">
          {recoveryEnrolled ? (
            <span className="user-menu-note" data-testid="recovery-enrolled">
              recovery phrase on
            </span>
          ) : (
            <button
              type="button"
              className="logout-link"
              data-testid="recovery-setup-open"
              onClick={() => setSettingUpRecovery(true)}
            >
              set up recovery phrase
            </button>
          )}
          <LogoutButton />
        </div>
      )}

      {settingUpRecovery && <RecoveryPhraseSetup onClose={() => setSettingUpRecovery(false)} />}
    </div>
  );
}
