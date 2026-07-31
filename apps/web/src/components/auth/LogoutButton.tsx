import { useNavigate } from 'react-router-dom';
import { useAuth } from '../../auth/useAuth';

/** Immediate logout, no confirmation. */
export function LogoutButton() {
  const { logout, isBusy } = useAuth();
  const navigate = useNavigate();

  const signOut = async () => {
    try {
      await logout();
    } finally {
      navigate('/');
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
