import { useAuth } from '../../auth/useAuth';

/**
 * Immediate logout, no confirmation. The reload is the teardown: `facade.logout`
 * closes this tab's engine client for good, so the login page needs a fresh one.
 */
export function LogoutButton() {
  const { logout, isBusy } = useAuth();

  const signOut = async () => {
    try {
      await logout();
    } finally {
      window.location.assign('/');
    }
  };

  return (
    <button
      type="button"
      data-testid="logout-button"
      className="logout-link"
      onClick={() => void signOut()}
      disabled={isBusy}
    >
      {isBusy ? 'logging out...' : 'logout'}
    </button>
  );
}
