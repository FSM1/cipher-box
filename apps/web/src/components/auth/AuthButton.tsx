import { useAuth } from '../../hooks/useAuth';

/**
 * Sign In button that opens Web3Auth modal.
 * Shows "Continue with [method]" for returning users.
 */
export function AuthButton() {
  const { login, isLoading } = useAuth();

  const handleClick = async () => {
    try {
      await login();
    } catch {
      // Error is already logged in useAuth
      // User can see the error in Web3Auth modal
    }
  };

  return (
    <button onClick={handleClick} disabled={isLoading} className="login-button">
      {isLoading ? 'connecting...' : '[CONNECT]'}
    </button>
  );
}
