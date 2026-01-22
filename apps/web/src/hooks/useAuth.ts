import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthFlow } from '../lib/web3auth/hooks';
import { authApi } from '../lib/api/auth';
import { vaultApi } from '../lib/api/vault';
import { useAuthStore } from '../stores/auth.store';
import { useVaultStore } from '../stores/vault.store';
import { useFolderStore } from '../stores/folder.store';
import { getDerivationVersion } from '../lib/crypto/signatureKeyDerivation';
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
    isConnected,
    isLoading: web3AuthLoading,
    userInfo,
    web3Auth,
    connect,
    disconnect,
    getIdToken,
    getPublicKey,
    getWalletAddress,
    getLoginType,
    isSocialLogin,
    deriveKeypairForExternalWallet,
    getDerivedPublicKeyHex,
    getKeypairForVault,
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

  // Get vault store actions
  const setVaultKeys = useVaultStore((state) => state.setVaultKeys);

  /**
   * Initialize vault for new users or load existing vault keys.
   * Called after successful backend authentication.
   */
  const initializeOrLoadVault = useCallback(
    async (connectedProvider: unknown, isExternalWallet: boolean): Promise<void> => {
      // Get user's secp256k1 keypair for vault operations
      let userKeypair: { publicKey: Uint8Array; privateKey: Uint8Array } | null = null;

      if (isExternalWallet) {
        // For external wallets, use the derived keypair stored in auth store
        const derivedKeypair = useAuthStore.getState().derivedKeypair;
        if (derivedKeypair) {
          userKeypair = derivedKeypair;
        }
      } else {
        // For social logins, get keypair from Web3Auth
        userKeypair = await getKeypairForVault(
          connectedProvider as Parameters<typeof getKeypairForVault>[0]
        );
      }

      if (!userKeypair) {
        console.error('Failed to get user keypair for vault operations');
        return;
      }

      try {
        // Try to fetch existing vault
        const existingVault = await vaultApi.getVault();

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
        // Check if it's a 404 (vault not found)
        const is404 = (error as { response?: { status?: number } })?.response?.status === 404;

        if (is404) {
          // New user - initialize vault
          const newVault = await initializeVault();
          const encryptedVault = await encryptVaultKeys(newVault, userKeypair.publicKey);
          const rootIpnsName = await deriveIpnsName(newVault.rootIpnsKeypair.publicKey);

          // Store vault on server
          const storedVault = await vaultApi.initVault({
            ownerPublicKey: bytesToHex(userKeypair.publicKey),
            encryptedRootFolderKey: bytesToHex(encryptedVault.encryptedRootFolderKey),
            encryptedRootIpnsPrivateKey: bytesToHex(encryptedVault.encryptedIpnsPrivateKey),
            rootIpnsPublicKey: bytesToHex(encryptedVault.rootIpnsPublicKey),
            rootIpnsName,
          });

          // Load decrypted keys into store
          setVaultKeys({
            rootFolderKey: newVault.rootFolderKey,
            rootIpnsKeypair: newVault.rootIpnsKeypair,
            rootIpnsName,
            vaultId: storedVault.id,
          });
        } else {
          // Other error - log but don't block login
          console.error('Failed to load vault:', error);
        }
      }
    },
    [getKeypairForVault, setVaultKeys]
  );

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
      let walletAddress: string | undefined = undefined;

      // 3. Handle key derivation based on login type
      if (isExternal) {
        // ADR-001: External wallet - derive keypair from signature
        // Get wallet address first (needed for JWT verification on backend)
        walletAddress = (await getWalletAddress(connectedProvider)) ?? undefined;
        if (!walletAddress) {
          throw new Error('Failed to get wallet address');
        }

        const derivedKeypair = await deriveKeypairForExternalWallet(connectedProvider);
        if (!derivedKeypair) {
          throw new Error('Failed to derive keypair from wallet signature');
        }

        // Store derived keypair in auth store (memory-only)
        setDerivedKeypair(derivedKeypair);
        setIsExternalWallet(true);

        // Use derived public key for backend authentication
        publicKey = getDerivedPublicKeyHex(derivedKeypair);
      } else {
        // Social login - get keypair from Web3Auth and store for crypto operations
        const socialKeypair = await getKeypairForVault(connectedProvider);
        if (socialKeypair) {
          setDerivedKeypair(socialKeypair);
        }
        publicKey = await getPublicKey(connectedProvider);
        setIsExternalWallet(false);
      }

      if (!idToken || !publicKey) {
        throw new Error('Failed to get credentials from Web3Auth');
      }

      // 4. Authenticate with backend
      const response = await authApi.login({
        idToken,
        publicKey,
        loginType,
        // ADR-001: Include wallet address and derivation version for external wallet users
        ...(isExternal && {
          walletAddress,
          derivationVersion: getDerivationVersion(),
        }),
      });

      // 5. Store access token (refresh token is in HTTP-only cookie)
      setAccessToken(response.accessToken);

      // 6. Initialize or load vault
      await initializeOrLoadVault(connectedProvider, isExternal);

      // 7. Remember auth method for "Continue with..." UX
      let authMethod: string;
      if (isExternal) {
        // External wallet: use connector name
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const connectorName = (web3Auth as any)?.connectedConnectorName;
        authMethod = connectorName || 'external_wallet';
      } else {
        // Social login: check multiple fields for the auth provider
        // Note: typeOfLogin and verifier are legacy Web3Auth properties, may not exist in v10+ types
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const info = userInfo as Record<string, any>;
        authMethod = info?.typeOfLogin || info?.verifier || info?.authConnection || 'google';
      }
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
    getWalletAddress,
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
      // [SECURITY: HIGH-02] Clear vault and folder stores BEFORE auth state
      // This ensures all cryptographic keys are zeroed from memory on logout
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();
      clearAuthState();

      // 4. Navigate to login
      navigate('/');
    } catch (error) {
      console.error('Logout failed:', error);
      // Still clear state even if backend fails
      // [SECURITY: HIGH-02] Clear all stores including crypto keys
      useFolderStore.getState().clearFolders();
      useVaultStore.getState().clearVaultKeys();
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

          // After successful session restore, initialize/load vault
          // Check if external wallet via auth store flag (persisted from original login)
          const isExternal = useAuthStore.getState().isExternalWallet;
          await initializeOrLoadVault(web3Auth?.provider, isExternal);
        } catch {
          // No valid session, stay on login page
          // Don't clear anything - user may just need to re-authenticate
        }
      }
    };
    restoreSession();
  }, [
    isConnected,
    isAuthenticated,
    isLoggingIn,
    setAccessToken,
    web3Auth?.provider,
    initializeOrLoadVault,
  ]);

  return {
    isLoading,
    isAuthenticated,
    lastAuthMethod,
    userInfo,
    login,
    logout,
  };
}
