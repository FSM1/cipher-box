import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

/**
 * User menu dropdown component.
 * Hover-triggered dropdown showing user email with settings and logout options.
 */
export function UserMenu() {
  const { logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  // TODO: Display user email from Core Kit session (Plan 04 Login UI)
  const email = 'User';

  const handleLogout = async () => {
    setIsOpen(false);
    await logout();
  };

  return (
    <div
      className="user-menu"
      data-testid="user-menu"
      onMouseEnter={() => setIsOpen(true)}
      onMouseLeave={() => setIsOpen(false)}
    >
      <button
        className="user-menu-trigger"
        type="button"
        aria-expanded={isOpen}
        aria-haspopup="true"
        onClick={() => setIsOpen(!isOpen)}
        onKeyDown={(e) => {
          if (e.key === 'Escape') setIsOpen(false);
        }}
      >
        <span className="user-menu-email">{email}</span>
        <span className="user-menu-caret">&#9660;</span>
      </button>

      {isOpen && (
        <div className="user-menu-dropdown" role="menu">
          <Link to="/settings" className="user-menu-item" role="menuitem">
            [settings]
          </Link>
          <button type="button" className="user-menu-item" role="menuitem" onClick={handleLogout}>
            [logout]
          </button>
        </div>
      )}
    </div>
  );
}
