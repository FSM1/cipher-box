import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCoreKitAuth } from '../lib/web3auth/hooks';
import { authApi } from '../lib/api/auth';
import { vaultApi } from '../lib/api/vault';
import { useAuthStore } from '../stores/auth.store';
import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import { useSyncStore } from '../stores/sync.store';
import { useDeviceRegistryStore } from '../stores/device-registry.store';
import { useMfaStore } from '../stores/mfa.store';
import {
  initializeVault,
  encryptVaultKeys,
  decryptVaultKeys,
  deriveIpnsName,
  hexToBytes,
  bytesToHex,
} from '@cipherbox/crypto';
import { getOrCreateDeviceIdentity } from '../lib/device/identity';
import { detectDeviceInfo } from '../lib/device/info';
import { initializeOrSyncRegistry } from '../services/device-registry.service';
import { clearFileSizeCache } from './useFileSize';

export function useAuth() {
  const navigate = useNavigate();
  const {
    isLoggedIn: coreKitLoggedIn,
    isInitialized: coreKitInitialized,
    isRequiredShare,
    loginWithGoogle: coreKitLoginGoogle,
    loginWithEmailOtp: coreKitLoginEmail,
    loginWithWallet: coreKitLoginWallet,
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
    setVaultKeypair,
    logout: clearAuthState,
  } = useAuthStore();

  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const restoringRef = useRef(false);

  // Stable refs for functions used in the session restoration effect.
  // This prevents the effect from re-firing when function references change.
  const initializeOrLoadVaultRef = useRef<(() => Promise<void>) | null>(null);
  const coreKitLogoutRef = useRef<(() => Promise<void>) | null>(null);

  // Pending auth state for REQUIRED_SHARE flow
  // Stored so completeRequiredShare() can resume after factor input
  const [pendingCipherboxJwt, setPendingCipherboxJwt] = useState<string | null>(null);
  const [pendingAuthMethod, setPendingAuthMethod] = useState<string | null>(null);

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
    setVaultKeypair(userKeypair);

    try {
      // Try to fetch existing vault
      const existingVault = await vaultApi.getVault();

      // Store TEE keys if available
      if (existingVault.teeKeys) {
        useAuthStore.getState().setTeeKeys(existingVault.teeKeys);
      }

      // Vault exists - decrypt keys and load into store
      // decryptVaultKeys derives the IPNS public key internally from the decrypted private key
      const decryptedVault = await decryptVaultKeys(
        {
          encryptedRootFolderKey: hexToBytes(existingVault.encryptedRootFolderKey),
          encryptedIpnsPrivateKey: hexToBytes(existingVault.encryptedRootIpnsPrivateKey),
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
        const newVault = await initializeVault(userKeypair.privateKey);
        const encryptedVault = await encryptVaultKeys(newVault, userKeypair.publicKey);
        const rootIpnsName = await deriveIpnsName(newVault.rootIpnsKeypair.publicKey);

        const storedVault = await vaultApi.initVault({
          ownerPublicKey: bytesToHex(userKeypair.publicKey),
          encryptedRootFolderKey: bytesToHex(encryptedVault.encryptedRootFolderKey),
          encryptedRootIpnsPrivateKey: bytesToHex(encryptedVault.encryptedIpnsPrivateKey),
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

    // Non-blocking device registry initialization (fire-and-forget)
    // Placed after vault load so registry failures never block login
    void (async () => {
      try {
        const deviceKeypair = await getOrCreateDeviceIdentity();
        const deviceInfo = detectDeviceInfo();
        const result = await initializeOrSyncRegistry({
          userPrivateKey: userKeypair.privateKey,
          userPublicKey: userKeypair.publicKey,
          deviceKeypair,
          deviceInfo: { ...deviceInfo, ipHash: '' },
        });
        if (result) {
          useDeviceRegistryStore
            .getState()
            .setRegistry(result.registry, result.ipnsName, deviceKeypair.deviceId);
        }
      } catch (error) {
        console.error('[Auth] Device registry init failed (non-blocking):', error);
      }
    })();
  }, [getVaultKeypair, setVaultKeypair, setVaultKeys]);

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
   * Complete the login flow after REQUIRED_SHARE is resolved.
   * Called after inputFactorKey() succeeds (from recovery phrase or cross-device approval).
   * Uses the stored pendingCipherboxJwt to call completeBackendAuth with the REAL publicKey
   * (since Core Kit is now LOGGED_IN), then navigates to /files.
   */
  const completeRequiredShare = useCallback(async (): Promise<void> => {
    const jwt = pendingCipherboxJwt;
    const method = pendingAuthMethod;

    if (!jwt || !method) {
      throw new Error('No pending auth info for REQUIRED_SHARE completion');
    }

    // Core Kit should now be LOGGED_IN after inputFactorKey()
    // Complete backend auth with the REAL publicKey (replaces the placeholder session)
    await completeBackendAuth(method, jwt);

    // Clear pending state
    setPendingCipherboxJwt(null);
    setPendingAuthMethod(null);

    // Navigate to files
    navigate('/files');
  }, [pendingCipherboxJwt, pendingAuthMethod, completeBackendAuth, navigate]);

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
        const {
          cipherboxJwt,
          email,
          userId,
          status: coreKitStatus,
        } = await coreKitLoginGoogle(googleIdToken);

        if (coreKitStatus === 'required_share') {
          // MFA enabled but device factor missing.
          // Store pending auth info for later completion after factor input.
          setPendingCipherboxJwt(cipherboxJwt);
          setPendingAuthMethod('google');

          // Obtain temporary backend access token so the new device can
          // call bulletin board API endpoints (device-approval/*).
          // Uses placeholder publicKey since Core Kit is in REQUIRED_SHARE
          // state and we can't export the TSS key yet.
          const tempLoginResponse = await authApi.login({
            idToken: cipherboxJwt,
            publicKey: `pending-core-kit-${userId}`,
            loginType: 'corekit',
          });
          setAccessToken(tempLoginResponse.accessToken);

          if (email) {
            setUserEmail(email);
          }

          // Do NOT call completeBackendAuth() or navigate('/files')
          // The component tree will see isRequiredShare === true and
          // render recovery/approval UI.
          return;
        }

        // Normal path: Core Kit logged in, proceed as before
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
    [isLoggingIn, coreKitLoginGoogle, completeBackendAuth, setAccessToken, setUserEmail, navigate]
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
        const { cipherboxJwt, userId, status: coreKitStatus } = await coreKitLoginEmail(email, otp);

        if (coreKitStatus === 'required_share') {
          setPendingCipherboxJwt(cipherboxJwt);
          setPendingAuthMethod('email');

          const tempLoginResponse = await authApi.login({
            idToken: cipherboxJwt,
            publicKey: `pending-core-kit-${userId}`,
            loginType: 'corekit',
          });
          setAccessToken(tempLoginResponse.accessToken);
          setUserEmail(email);
          return;
        }

        // Normal path
        await completeBackendAuth('email', cipherboxJwt);
        setUserEmail(email);
        navigate('/files');
      } catch (error) {
        console.error('[useAuth] Email login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginEmail, completeBackendAuth, setAccessToken, setUserEmail, navigate]
  );

  /**
   * Login with Wallet (SIWE).
   * Flow: Wallet connects + signs SIWE message -> backend verifies ->
   * CipherBox JWT -> Core Kit loginWithJWT -> backend /auth/login (corekit type)
   */
  const loginWithWallet = useCallback(
    async (cipherboxJwt: string, userId: string): Promise<void> => {
      if (isLoggingIn) return;
      setIsLoggingIn(true);
      try {
        // 1. Core Kit login via CipherBox identity provider
        const { status: coreKitStatus } = await coreKitLoginWallet(cipherboxJwt, userId);

        if (coreKitStatus === 'required_share') {
          setPendingCipherboxJwt(cipherboxJwt);
          setPendingAuthMethod('wallet');

          const tempLoginResponse = await authApi.login({
            idToken: cipherboxJwt,
            publicKey: `pending-core-kit-${userId}`,
            loginType: 'corekit',
          });
          setAccessToken(tempLoginResponse.accessToken);
          return;
        }

        // Normal path
        await completeBackendAuth('wallet', cipherboxJwt);
        navigate('/files');
      } catch (error) {
        console.error('[useAuth] Wallet login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginWallet, completeBackendAuth, setAccessToken, navigate]
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
      useDeviceRegistryStore.getState().clearRegistry();
      useMfaStore.getState().reset();
      clearFileSizeCache();
      clearAuthState();

      // 4. Clear pending REQUIRED_SHARE state
      setPendingCipherboxJwt(null);
      setPendingAuthMethod(null);

      // 5. Navigate to login
      navigate('/');
    } catch (error) {
      console.error('[useAuth] Logout failed:', error);
      // Still clear state even if backend fails
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();
      useSyncStore.getState().reset();
      useDeviceRegistryStore.getState().clearRegistry();
      useMfaStore.getState().reset();
      clearFileSizeCache();
      clearAuthState();
      setPendingCipherboxJwt(null);
      setPendingAuthMethod(null);
      navigate('/');
    } finally {
      setIsLoggingOut(false);
    }
  }, [accessToken, coreKitLogout, clearAuthState, navigate, isLoggingOut]);

  // Keep function refs up-to-date for use in session restoration effect.
  // Using refs prevents the effect from re-firing when function identities change.
  initializeOrLoadVaultRef.current = initializeOrLoadVault;
  coreKitLogoutRef.current = coreKitLogout;

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
          await initializeOrLoadVaultRef.current?.();
        } catch {
          // No valid backend session -- user needs to re-login
          // Core Kit session exists but backend cookie expired
          // Clear Core Kit session to avoid inconsistent state
          try {
            await coreKitLogoutRef.current?.();
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
  }, [coreKitLoggedIn, isAuthenticated, isLoggingIn, setAccessToken, setUserEmail]);

  return {
    isLoading,
    isAuthenticated,
    isRequiredShare,
    lastAuthMethod,
    userEmail,
    pendingAuthMethod,
    login,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
    completeRequiredShare,
    logout,
  };
}
