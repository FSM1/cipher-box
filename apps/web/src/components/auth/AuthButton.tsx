import { useAuth } from '../../hooks/useAuth';
import { useAuthStore } from '../../stores/auth.store';

/**
 * Sign In button that opens Web3Auth modal.
 * Shows "Continue with [method]" for returning users.
 */
export function AuthButton() {
  const { login, isLoading } = useAuth();
  const { lastAuthMethod } = useAuthStore();

  // Format the button text based on last auth method
  const formatAuthMethod = (method: string | null): string => {
    if (!method) return 'Sign In';

    // Format common auth methods for display
    const methodMap: Record<string, string> = {
      google: 'Google',
      github: 'GitHub',
      twitter: 'Twitter',
      discord: 'Discord',
      apple: 'Apple',
      email_passwordless: 'Email',
      metamask: 'MetaMask',
      wallet_connect_v2: 'WalletConnect',
      coinbase: 'Coinbase',
      phantom: 'Phantom',
    };

    const displayName = methodMap[method.toLowerCase()] || method;
    return `Continue with ${displayName}`;
  };

  const buttonText = formatAuthMethod(lastAuthMethod);

  const handleClick = async () => {
    try {
      await login();
    } catch {
      // Error is already logged in useAuth
      // User can see the error in Web3Auth modal
    }
  };

  return (
    <button onClick={handleClick} disabled={isLoading} className="auth-button">
      {isLoading ? 'Connecting...' : buttonText}
    </button>
  );
}
