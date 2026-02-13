import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCoreKitAuth } from '../lib/web3auth/hooks';
import { authApi } from '../lib/api/auth';
import { vaultApi } from '../lib/api/vault';
import { useAuthStore } from '../stores/auth.store';
import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import { useSyncStore } from '../stores/sync.store';
import {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  deriveIpnsName,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';

export function useAuth() {
  const navigate = useNavigate();
  const {
    isLoggedIn: coreKitLoggedIn,
    isInitialized: coreKitInitialized,
    loginWithGoogle: coreKitLoginGoogle,
    loginWithEmailOtp: coreKitLoginEmail,
    getVaultKeypair,
    getPublicKeyHex,
    logout: coreKitLogout,
  } = useCoreKitAuth();
  const {
    accessToken,
    isAuthenticated,
    lastAuthMethod,
    userEmail,
    setAccessToken,
    setLastAuthMethod,
    setUserEmail,
    setDerivedKeypair,
    logout: clearAuthState,
  } = useAuthStore();

  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const restoringRef = useRef(false);

  const isLoading = !coreKitInitialized || isLoggingIn || isLoggingOut;

  // Get vault store actions
  const setVaultKeys = useVaultStore((state) => state.setVaultKeys);

  /**
   * Initialize vault for new users or load existing vault keys.
   * Called after successful backend authentication.
   * Uses Core Kit's getVaultKeypair() instead of PnP provider.
   */
  const initializeOrLoadVault = useCallback(async (): Promise<void> => {
    // Get user's secp256k1 keypair from Core Kit TSS export
    const userKeypair = await getVaultKeypair();

    if (!userKeypair) {
      throw new Error('Failed to get vault keypair from Core Kit');
    }

    // Store keypair in auth store for crypto operations
    setDerivedKeypair(userKeypair);

    try {
      // Try to fetch existing vault
      const existingVault = await vaultApi.getVault();

      // Store TEE keys if available
      if (existingVault.teeKeys) {
        useAuthStore.getState().setTeeKeys(existingVault.teeKeys);
      }

      // Vault exists - decrypt keys and load into store
      const decryptedVault = await decryptVaultKeys(
        {
          encryptedRootFolderKey: hexToBytes(existingVault.encryptedRootFolderKey),
          encryptedIpnsPrivateKey: hexToBytes(existingVault.encryptedRootIpnsPrivateKey),
          rootIpnsPublicKey: hexToBytes(existingVault.rootIpnsPublicKey),
        },
        userKeypair.privateKey
      );

      setVaultKeys({
        rootFolderKey: decryptedVault.rootFolderKey,
        rootIpnsKeypair: decryptedVault.rootIpnsKeypair,
        rootIpnsName: existingVault.rootIpnsName,
        vaultId: existingVault.id,
      });
    } catch (error) {
      const is404 = (error as { response?: { status?: number } })?.response?.status === 404;

      if (is404) {
        // New user - initialize vault
        console.log(
          '[Auth] New user on Core Kit. If migrating from PnP, vault re-initialization may be needed.'
        );
        const newVault = await initializeVault();
        const encryptedVault = await encryptVaultKeys(newVault, userKeypair.publicKey);
        const rootIpnsName = await deriveIpnsName(newVault.rootIpnsKeypair.publicKey);

        const storedVault = await vaultApi.initVault({
          ownerPublicKey: bytesToHex(userKeypair.publicKey),
          encryptedRootFolderKey: bytesToHex(encryptedVault.encryptedRootFolderKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encryptedVault.encryptedIpnsPrivateKey),
          rootIpnsPublicKey: bytesToHex(encryptedVault.rootIpnsPublicKey),
          rootIpnsName,
        });

        if (storedVault.teeKeys) {
          useAuthStore.getState().setTeeKeys(storedVault.teeKeys);
        }

        setVaultKeys({
          rootFolderKey: newVault.rootFolderKey,
          rootIpnsKeypair: newVault.rootIpnsKeypair,
          rootIpnsName,
          vaultId: storedVault.id,
          isNewVault: true,
        });
      } else {
        console.error('[useAuth] Failed to load vault:', error);
        throw error;
      }
    }
  }, [getVaultKeypair, setDerivedKeypair, setVaultKeys]);

  /**
   * Complete backend authentication after Core Kit login.
   * Sends the CipherBox-issued JWT (which we used for Core Kit loginWithJWT)
   * to the backend with loginType 'corekit'. The backend verifies it against
   * its own JWKS since CipherBox is the identity provider.
   */
  const completeBackendAuth = useCallback(
    async (authMethod: string, cipherboxJwt: string): Promise<void> => {
      // 1. Get real publicKey from Core Kit TSS export
      const publicKey = await getPublicKeyHex();
      if (!publicKey) {
        throw new Error('Failed to get publicKey from Core Kit');
      }

      // publicKey available for debugging via DevTools if needed

      // 2. Authenticate with CipherBox backend
      // Backend verifies our CipherBox JWT and resolves placeholder publicKey
      const response = await authApi.login({
        idToken: cipherboxJwt,
        publicKey,
        loginType: 'corekit',
      });

      // 3. Store access token (refresh token in HTTP-only cookie)
      setAccessToken(response.accessToken);

      // 4. Remember auth method for UX
      setLastAuthMethod(authMethod);

      // 5. Initialize or load vault
      await initializeOrLoadVault();
    },
    [getPublicKeyHex, setAccessToken, setLastAuthMethod, initializeOrLoadVault]
  );

  /**
   * Login with Google OAuth token.
   * Flow: Google idToken -> CipherBox backend -> CipherBox JWT ->
   * Core Kit loginWithJWT -> backend /auth/login (corekit type)
   */
  const loginWithGoogle = useCallback(
    async (googleIdToken: string): Promise<void> => {
      if (isLoggingIn) return;
      setIsLoggingIn(true);
      try {
        // 1. Core Kit login via CipherBox identity provider
        const { cipherboxJwt, email } = await coreKitLoginGoogle(googleIdToken);

        // 2. Complete backend auth + vault init
        await completeBackendAuth('google', cipherboxJwt);

        // 3. Store email for UI display (returned from identity endpoint)
        if (email) {
          setUserEmail(email);
        }

        // 4. Navigate to files
        navigate('/files');
      } catch (error) {
        console.error('[useAuth] Google login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginGoogle, completeBackendAuth, setUserEmail, navigate]
  );

  /**
   * Login with Email OTP.
   * Flow: email+otp -> CipherBox backend -> CipherBox JWT ->
   * Core Kit loginWithJWT -> backend /auth/login (corekit type)
   */
  const loginWithEmail = useCallback(
    async (email: string, otp: string): Promise<void> => {
      if (isLoggingIn) return;
      setIsLoggingIn(true);
      try {
        // 1. Core Kit login via CipherBox identity provider
        const { cipherboxJwt } = await coreKitLoginEmail(email, otp);

        // 2. Complete backend auth + vault init
        await completeBackendAuth('email_passwordless', cipherboxJwt);

        // 4. Store email for display in UI
        setUserEmail(email);

        // 5. Navigate to files
        navigate('/files');
      } catch (error) {
        console.error('[useAuth] Email login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginEmail, completeBackendAuth, setUserEmail, navigate]
  );

  /**
   * Legacy login() for backward compatibility with AuthButton.
   * With Core Kit, login requires specifying the auth method.
   * This will be replaced by the new Login UI in Plan 04.
   */
  const login = useCallback(async () => {
    // Plan 04 will build the new login UI with method selection.
    // For now, this is a no-op placeholder that AuthButton calls.
    console.warn(
      '[useAuth] login() called without method -- ' +
        'use loginWithGoogle() or loginWithEmail() instead. ' +
        'Plan 04 will provide the new Login UI.'
    );
  }, []);

  // Complete logout: Backend -> Core Kit -> Clear state
  const logout = useCallback(async () => {
    if (isLoggingOut) return;

    setIsLoggingOut(true);
    try {
      // 1. Call backend logout (clears cookie)
      if (accessToken) {
        try {
          await authApi.logout();
        } catch {
          // Ignore errors -- we'll clear state anyway
        }
      }

      // 2. Logout Core Kit (clears session from localStorage)
      await coreKitLogout();

      // 3. Clear local state
      // [SECURITY: HIGH-02] Clear vault and folder stores
      // BEFORE auth state to zero crypto keys from memory
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();
      useSyncStore.getState().reset();
      clearAuthState();

      // 4. Navigate to login
      navigate('/');
    } catch (error) {
      console.error('[useAuth] Logout failed:', error);
      // Still clear state even if backend fails
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();
      useSyncStore.getState().reset();
      clearAuthState();
      navigate('/');
    } finally {
      setIsLoggingOut(false);
    }
  }, [accessToken, coreKitLogout, clearAuthState, navigate, isLoggingOut]);

  // Session restoration: if Core Kit restores a session from localStorage
  // on init, we have LOGGED_IN status without going through login flow.
  // Complete backend auth + vault loading.
  useEffect(() => {
    const restoreSession = async () => {
      // Only restore if Core Kit has a session but we don't have
      // a backend access token yet
      if (coreKitLoggedIn && !isAuthenticated && !isLoggingIn && !restoringRef.current) {
        restoringRef.current = true;
        setIsLoggingIn(true);
        try {
          // Try to refresh using the HTTP-only cookie first
          const response = await authApi.refresh();
          setAccessToken(response.accessToken);

          // Restore email from backend if available
          if (response.email) {
            setUserEmail(response.email);
          }

          // Load vault keys from Core Kit keypair
          await initializeOrLoadVault();
        } catch {
          // No valid backend session -- user needs to re-login
          // Core Kit session exists but backend cookie expired
          // Clear Core Kit session to avoid inconsistent state
          try {
            await coreKitLogout();
          } catch {
            // Ignore logout errors during cleanup
          }
        } finally {
          restoringRef.current = false;
          setIsLoggingIn(false);
        }
      }
    };
    restoreSession();
  }, [
    coreKitLoggedIn,
    isAuthenticated,
    isLoggingIn,
    setAccessToken,
    setUserEmail,
    initializeOrLoadVault,
    coreKitLogout,
  ]);

  return {
    isLoading,
    isAuthenticated,
    lastAuthMethod,
    userEmail,
    login,
    loginWithGoogle,
    loginWithEmail,
    logout,
  };
}
