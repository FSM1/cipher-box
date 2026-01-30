import { useState } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../../hooks/useAuth';

/**
 * User menu dropdown component.
 * Hover-triggered dropdown showing user email with settings and logout options.
 */
export function UserMenu() {
  const { userInfo, logout } = useAuth();
  const [isOpen, setIsOpen] = useState(false);

  // Get user email from Web3Auth user info
  const email = userInfo?.email || 'User';

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
      <button className="user-menu-trigger" type="button">
        <span className="user-menu-email">{email}</span>
        <span className="user-menu-caret">&#9660;</span>
      </button>

      {isOpen && (
        <div className="user-menu-dropdown">
          <Link to="/settings" className="user-menu-item">
            [settings]
          </Link>
          <button type="button" className="user-menu-item" onClick={handleLogout}>
            [logout]
          </button>
        </div>
      )}
    </div>
  );
}
