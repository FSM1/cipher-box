import { useAuth } from '../../hooks/useAuth';

interface AuthButtonProps {
  apiDown?: boolean;
}

/**
 * Sign In button that opens Web3Auth modal.
 * Disables with [API OFFLINE] text when API health check fails.
 */
export function AuthButton({ apiDown }: AuthButtonProps) {
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
    <button
      onClick={handleClick}
      disabled={isLoading || apiDown}
      className={['login-button', apiDown ? 'login-button--api-down' : '']
        .filter(Boolean)
        .join(' ')}
    >
      {isLoading ? 'connecting...' : apiDown ? '[API OFFLINE]' : '[CONNECT]'}
    </button>
  );
}
