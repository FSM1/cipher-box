import { useState } from 'react';
import { Link } from 'react-router-dom';
import { LogoutButton } from '../auth/LogoutButton';
import { useAuthState } from '../../stores/auth.store';

/**
 * Who is signed in, and the way out. Escape is handled on the container, not the
 * trigger, so it still closes once focus moves into the dropdown.
 */
export function UserMenu() {
  const { email } = useAuthState();
  const [isOpen, setIsOpen] = useState(false);

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
          {/* The recovery phrase, this device and the vault's own settings all
              live on the settings route (blueprint/web-client.md "Composition"). */}
          <Link className="logout-link" to="/settings" data-testid="user-menu-settings">
            settings
          </Link>
          <LogoutButton />
        </div>
      )}
    </div>
  );
}
