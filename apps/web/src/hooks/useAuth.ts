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
      // 1. Open Web3Auth modal
      await connect();

      // 2. Get credentials from Web3Auth
      const idToken = await getIdToken();
      const publicKey = await getPublicKey();
      const loginType = getLoginType();

      if (!idToken || !publicKey) {
        throw new Error('Failed to get credentials from Web3Auth');
      }

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

      // 6. Navigate to dashboard
      navigate('/dashboard');
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setIsLoggingIn(false);
    }
  }, [
    isLoggingIn,
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
