import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthFlow } from '../lib/web3auth/hooks';
import { authApi } from '../lib/api/auth';
import { useAuthStore } from '../stores/auth.store';

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
  } = useAuthFlow();
  const {
    accessToken,
    isAuthenticated,
    lastAuthMethod,
    setAccessToken,
    setLastAuthMethod,
    logout: clearAuthState,
  } = useAuthStore();

  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);

  const isLoading = web3AuthLoading || isLoggingIn || isLoggingOut;

  // Complete login: Web3Auth -> Backend
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
      const publicKey = await getPublicKey(connectedProvider);
      const loginType = getLoginType();

      if (!idToken || !publicKey) {
        throw new Error('Failed to get credentials from Web3Auth');
      }

      // Log for verification of grouped connections
      console.log('=== Login Verification ===');
      console.log('Login Type:', loginType);
      console.log('Public Key:', publicKey);
      console.log('========================');

      // 3. Authenticate with backend
      const response = await authApi.login({
        idToken,
        publicKey,
        loginType,
      });

      // 4. Store access token (refresh token is in HTTP-only cookie)
      setAccessToken(response.accessToken);

      // 5. Remember auth method for "Continue with..." UX
      const authMethod = userInfo?.authConnection || 'unknown';
      setLastAuthMethod(authMethod);

      // 6. Close modal (Web3Auth SDK sometimes leaves it open)
      try {
        // @ts-expect-error - loginModal exists at runtime
        web3Auth?.loginModal?.closeModal?.();
      } catch {
        // Ignore if method doesn't exist
      }

      // 7. Navigate to dashboard
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
