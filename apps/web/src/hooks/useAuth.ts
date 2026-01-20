import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthFlow } from '../lib/web3auth/hooks';
import { authApi } from '../lib/api/auth';
import { useAuthStore } from '../stores/auth.store';
import { getDerivationVersion } from '../lib/crypto/signatureKeyDerivation';

export function useAuth() {
  const navigate = useNavigate();
  const {
    isConnected,
    isLoading: web3AuthLoading,
    userInfo,
    web3Auth,
    connect,
    disconnect,
    getIdToken,
    getPublicKey,
    getLoginType,
    isSocialLogin,
    deriveKeypairForExternalWallet,
    getDerivedPublicKeyHex,
  } = useAuthFlow();
  const {
    accessToken,
    isAuthenticated,
    lastAuthMethod,
    setAccessToken,
    setLastAuthMethod,
    setDerivedKeypair,
    setIsExternalWallet,
    logout: clearAuthState,
  } = useAuthStore();

  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const isLoading = web3AuthLoading || isLoggingIn || isLoggingOut;

  // Complete login: Web3Auth -> (Optional Key Derivation) -> Backend
  const login = useCallback(async () => {
    if (isLoggingIn) return;

    setIsLoggingIn(true);
    try {
      // 1. Open Web3Auth modal (configured with grouped connection)
      const connectedProvider = await connect();

      if (!connectedProvider) {
        throw new Error('Web3Auth connection cancelled or failed');
      }

      // 2. Get credentials from Web3Auth
      const idToken = await getIdToken();
      const loginType = getLoginType();
      const isExternal = !isSocialLogin();

      let publicKey: string | null = null;

      // 3. Handle key derivation based on login type
      if (isExternal) {
        // ADR-001: External wallet - derive keypair from signature
        console.log('=== External Wallet Login ===');
        console.log('Requesting signature for key derivation...');

        const derivedKeypair = await deriveKeypairForExternalWallet(connectedProvider);
        if (!derivedKeypair) {
          throw new Error('Failed to derive keypair from wallet signature');
        }

        // Store derived keypair in auth store (memory-only)
        setDerivedKeypair(derivedKeypair);
        setIsExternalWallet(true);

        // Use derived public key for backend authentication
        publicKey = getDerivedPublicKeyHex(derivedKeypair);

        console.log('Key derivation successful');
        console.log('Derived Public Key:', publicKey);
        console.log('=============================');
      } else {
        // Social login - get public key directly from Web3Auth
        publicKey = await getPublicKey(connectedProvider);
        setIsExternalWallet(false);

        console.log('=== Social Login ===');
        console.log('Login Type:', loginType);
        console.log('Public Key:', publicKey);
        console.log('====================');
      }

      if (!idToken || !publicKey) {
        throw new Error('Failed to get credentials from Web3Auth');
      }

      // 4. Authenticate with backend
      const response = await authApi.login({
        idToken,
        publicKey,
        loginType,
        // ADR-001: Include derivation version for external wallet users
        ...(isExternal && { derivationVersion: getDerivationVersion() }),
      });

      // 5. Store access token (refresh token is in HTTP-only cookie)
      setAccessToken(response.accessToken);

      // 6. Remember auth method for "Continue with..." UX
      const authMethod = userInfo?.authConnection || 'unknown';
      setLastAuthMethod(authMethod);

      // 7. Close modal (Web3Auth SDK sometimes leaves it open)
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        (web3Auth as any)?.loginModal?.closeModal?.();
      } catch {
        // Ignore if method doesn't exist
      }

      // 8. Navigate to dashboard
      navigate('/dashboard');
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setIsLoggingIn(false);
    }
  }, [
    isLoggingIn,
    web3Auth,
    connect,
    getIdToken,
    getPublicKey,
    getLoginType,
    isSocialLogin,
    deriveKeypairForExternalWallet,
    getDerivedPublicKeyHex,
    setDerivedKeypair,
    setIsExternalWallet,
    userInfo,
    setAccessToken,
    setLastAuthMethod,
    navigate,
  ]);

  // Complete logout: Backend -> Web3Auth -> Clear state
  const logout = useCallback(async () => {
    if (isLoggingOut) return;

    setIsLoggingOut(true);
    try {
      // 1. Call backend logout (clears cookie)
      if (accessToken) {
        try {
          await authApi.logout();
        } catch {
          // Ignore errors - we'll clear state anyway
        }
      }

      // 2. Disconnect Web3Auth
      await disconnect();

      // 3. Clear local state
      clearAuthState();

      // 4. Navigate to login
      navigate('/');
    } catch (error) {
      console.error('Logout failed:', error);
      // Still clear state even if backend fails
      clearAuthState();
      navigate('/');
    } finally {
      setIsLoggingOut(false);
    }
  }, [accessToken, disconnect, clearAuthState, navigate, isLoggingOut]);

  // Try to restore session on mount
  useEffect(() => {
    const restoreSession = async () => {
      // Only try to restore if Web3Auth is connected but we don't have an access token
      if (isConnected && !isAuthenticated && !isLoggingIn) {
        try {
          // Try to refresh using the HTTP-only cookie
          const response = await authApi.refresh();
          setAccessToken(response.accessToken);
        } catch {
          // No valid session, stay on login page
          // Don't clear anything - user may just need to re-authenticate
        }
      }
    };
    restoreSession();
  }, [isConnected, isAuthenticated, isLoggingIn, setAccessToken]);

  return {
    isLoading,
    isAuthenticated,
    lastAuthMethod,
    userInfo,
    login,
    logout,
  };
}
