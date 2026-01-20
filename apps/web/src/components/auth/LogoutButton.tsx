import { useAuth } from '../../hooks/useAuth';

/**
 * Logout button that disconnects Web3Auth and clears session.
 * Per 02-CONTEXT.md: Immediate logout on click, no confirmation.
 */
export function LogoutButton() {
  const { logout, isLoading } = useAuth();

  const handleClick = async () => {
    try {
      await logout();
    } catch {
      // Error is already logged in useAuth
      // User will be redirected regardless
    }
  };

  return (
    <button onClick={handleClick} disabled={isLoading} className="logout-button">
      {isLoading ? 'Logging out...' : 'Logout'}
    </button>
  );
}
