import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCoreKitAuth } from '../lib/web3auth/hooks';
import { useCoreKit } from '../lib/web3auth/core-kit-provider';
import { authApi } from '../lib/api/auth';
import { vaultApi } from '../lib/api/vault';
import { useAuthStore } from '../stores/auth.store';
import { useFolderStore } from '../stores/folder.store';
import { useVaultStore } from '../stores/vault.store';
import { useDeviceRegistryStore } from '../stores/device-registry.store';
import { clearAllUserStores } from '../lib/clear-user-stores';
import { initSdkClient, createBootstrapClient } from '../lib/sdk-provider';
import { setFaroUser, clearFaroUser } from '../lib/faro';
// api-config.ts handles setApiClientConfig at module load time
import {
  deriveVaultIpnsKeypair,
  deriveVaultKeyIpnsKeypair,
  deriveByoConfigIpnsKeypair,
  bytesToHex,
  unwrapKey,
  clearBytes,
} from '@cipherbox/crypto';
import type { ByoIpfsConfig } from '@cipherbox/core';
import type { PinningConfig } from '@cipherbox/sdk';
import { getOrCreateDeviceIdentity } from '../lib/device/identity';
import { detectDeviceInfo, computeIpHash } from '../lib/device/info';
import { initializeOrSyncRegistry } from '../services/device-registry.service';
import { useBinStore } from '../stores/bin.store';
import { loadVaultSettings } from '../services/vault-settings.service';
import { useVaultSettingsStore } from '../stores/vault-settings.store';
import { apiUrl as sdkApiUrl } from '../lib/api-config';
import {
  triggerOwnerReconcileOnLogin,
  runOwnerReconcileForFolder,
} from '../services/owner-reconcile.service';
import {
  buildRotationClientCallbacks,
  resumeInterruptedRotation,
} from '../services/rotation-driver.service';
import { rotationHighWater } from '../services/rotation-state.service';
import { logger } from '../lib/logger';

// Module-level deduplication for vault init/load.
// Multiple React effects can call initializeOrLoadVault concurrently after
// page reload (session restore + login flow). Without deduplication, both
// see getVault() → 404, both attempt vault init, and the second hits a
// duplicate key constraint on folder_ipns.
let vaultInitPromise: Promise<void> | null = null;

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
  const { syncStatus } = useCoreKit();
  const {
    accessToken,
    isAuthenticated,
    lastAuthMethod,
    userEmail,
    setAccessToken,
    setAuthenticated,
    setLastAuthMethod,
    setUserEmail,
    setVaultKeypair,
  } = useAuthStore();

  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoggingOut, setIsLoggingOut] = useState(false);
  const restoringRef = useRef(false);

  // Stable refs for functions used in the session restoration effect.
  // This prevents the effect from re-firing when function references change.
  const initializeOrLoadVaultRef = useRef<(() => Promise<void>) | null>(null);
  const coreKitLogoutRef = useRef<(() => Promise<void>) | null>(null);

  // Pending auth state for REQUIRED_SHARE flow.
  // Stored in Zustand (not useState) so the state is shared across all
  // useAuth() hook instances — Login.tsx sets it, useDeviceApproval reads it
  // via its own useAuth() call.
  const pendingAuthMethod = useAuthStore((s) => s.pendingAuthMethod);
  const setPendingAuth = useAuthStore((s) => s.setPendingAuth);

  // `coreKitLoggedIn && !isAuthenticated` covers the session-restore window: after
  // a reload CoreKit re-initializes (coreKitInitialized flips true) a beat before
  // the restoreSession effect sets isLoggingIn/isAuthenticated. Without this term
  // there is a transient where !isLoading && !isAuthenticated are both true, so a
  // protected route mounting in that gap (e.g. opening /bin right after a reload)
  // wrongly redirects to /login. Keeping isLoading true until restore resolves
  // closes the gap; a genuinely logged-out user has coreKitLoggedIn false, so the
  // login redirect still fires.
  const isLoading =
    !coreKitInitialized || isLoggingIn || isLoggingOut || (coreKitLoggedIn && !isAuthenticated);

  // Get vault store actions
  const setVaultKeys = useVaultStore((state) => state.setVaultKeys);

  /**
   * Initialize vault for new users or load existing vault keys.
   * Called after successful backend authentication.
   * Uses Core Kit's getVaultKeypair() instead of PnP provider.
   *
   * Deduplicated at module level: concurrent callers share a single
   * in-flight promise to prevent double vault init on page reload.
   */
  const initializeOrLoadVault = useCallback(async (): Promise<void> => {
    if (vaultInitPromise) return vaultInitPromise;
    const doInit = async () => {
      // Get user's secp256k1 keypair from Core Kit TSS export
      const userKeypair = await getVaultKeypair();

      if (!userKeypair) {
        throw new Error('Failed to get vault keypair from Core Kit');
      }

      // Store keypair in auth store for crypto operations
      setVaultKeypair(userKeypair);

      // Throwaway facade client for vault-bootstrap/config-blob operations
      // that must run BEFORE rootIpnsName/rootFolderKey are known -- this
      // client mints/loads the very keys the REAL SDK client (initSdkClient
      // below) needs to be constructed. These facade methods only read
      // `ctx` (apiUrl/getAccessToken/axiosInstance) or caller-supplied key
      // material passed directly as arguments; they never touch
      // rootIpnsName/rootFolderKey/folderTree, so the placeholder values
      // createBootstrapClient uses internally are safe. Destroyed in the
      // finally block below once no longer needed (D-09) -- it is a fully
      // separate instance from the real sdkClient constructed later.
      const bootstrapClient = createBootstrapClient({
        apiUrl: sdkApiUrl,
        getAccessToken: async () => useAuthStore.getState().accessToken || '',
        vaultKeypair: { publicKey: userKeypair.publicKey, privateKey: userKeypair.privateKey },
      });

      try {
        // Isolate getVault() so only its 404 triggers new-user initialization.
        // Downstream errors (IPNS resolve, IPFS fetch) must not be misclassified.
        let existingVault: Awaited<ReturnType<typeof vaultApi.getVault>> | null = null;
        try {
          existingVault = await vaultApi.getVault();
        } catch (error) {
          const is404 = (error as { response?: { status?: number } })?.response?.status === 404;
          if (!is404) {
            logger.error('[useAuth] Failed to load vault:', error);
            throw error;
          }
        }

        if (existingVault) {
          // Store TEE keys if available
          if (existingVault.teeKeys) {
            useAuthStore.getState().setTeeKeys(existingVault.teeKeys);
          }

          // Load vault v3 key blob from dedicated vault key IPNS (separate from root folder IPNS)
          const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(userKeypair.privateKey);

          const resolved = await bootstrapClient.resolveConfigBlob(vaultKeyKeypair.ipnsName);
          if (!resolved) throw new Error('Vault key IPNS name not found');

          const blobBytes = await bootstrapClient.downloadBytes(resolved.cid);

          // Deserialize + ECIES-unwrap v3 blob (only rootReadKey + rootWriteKey;
          // IPNS keypair is derived) via the SDK facade
          const { rootReadKey, rootWriteKey } = await bootstrapClient.deserializeVault(
            blobBytes,
            userKeypair.privateKey
          );

          // IPNS keypair is deterministically derived from user private key (not in blob)
          const rootIpnsKeypair = await deriveVaultIpnsKeypair(userKeypair.privateKey);

          setVaultKeys({
            rootReadKey,
            rootWriteKey,
            rootIpnsKeypair,
            rootIpnsName: existingVault.rootIpnsName,
            vaultId: existingVault.id,
          });
        } else {
          // New user -- initialize vault with v3 key blob + root Node
          logger.info('[Auth] New user -- initializing vault (v3)');
          const newVault = await bootstrapClient.bootstrapVaultKeys(userKeypair.privateKey);

          // Derive vault key IPNS keypair (separate from root folder IPNS)
          const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(userKeypair.privateKey);
          const vaultKeyIpnsName = vaultKeyKeypair.ipnsName;

          // 1. ECIES-wrap + serialize v3 key blob, publish to vault key IPNS
          // serializeVault stores only rootReadKey + rootWriteKey (IPNS keypair is derived)
          const v3Blob = await bootstrapClient.serializeVault(newVault, userKeypair.publicKey);

          const keyBlobUpload = await bootstrapClient.uploadBytes(v3Blob);
          const keyPublishResult = await bootstrapClient.publishConfigBlob({
            ipnsPrivateKey: vaultKeyKeypair.privateKey,
            ipnsName: vaultKeyIpnsName,
            metadataCid: keyBlobUpload.cid,
            sequenceNumber: 1n,
          });
          if (!keyPublishResult.success) {
            throw new Error('Failed to publish vault key blob to IPNS');
          }

          // 2. Publish an empty kind:'root' Node (write-body carries the root IPNS
          // signing key) to the root IPNS name at sequenceNumber 1n. The name is
          // derived internally by publishEmptyRootNode from rootIpnsKeypair.publicKey
          // and returned below (T-68.1-03-02).
          const { ipnsName: rootIpnsName } = await bootstrapClient.publishEmptyRootNode({
            rootIpnsKeypair: newVault.rootIpnsKeypair,
            rootReadKey: newVault.rootReadKey,
            rootWriteKey: newVault.rootWriteKey,
            // New users have no TEE enrollment yet -- teeKeys stays undefined.
          });

          // 3. Register the vault with the API. Zero-crypto v2 schema: only
          // ownerPublicKey + rootIpnsName cross the wire, never plaintext/crypto
          // key material (CLAUDE.md rule 3/6, T-68.1-03-01).
          const registeredVault = await vaultApi.initVault({
            ownerPublicKey: bytesToHex(userKeypair.publicKey),
            rootIpnsName,
          });

          setVaultKeys({
            rootReadKey: newVault.rootReadKey,
            rootWriteKey: newVault.rootWriteKey,
            rootIpnsKeypair: newVault.rootIpnsKeypair,
            rootIpnsName,
            vaultId: registeredVault.id,
          });
        }

        // Load BYO pinning config from encrypted IPNS entry (if configured).
        // Gracefully degrades to cipherbox-only mode on any failure.
        const loadByoConfig = async (
          userPrivateKey: Uint8Array
        ): Promise<PinningConfig | undefined> => {
          // Time-bound the entire lookup so a hung IPFS peer can't block login
          const BYO_LOAD_TIMEOUT_MS = 10_000;
          const inner = async (): Promise<PinningConfig | undefined> => {
            const byoKeypair = await deriveByoConfigIpnsKeypair(userPrivateKey);
            const ipnsName = byoKeypair.ipnsName;

            const resolved = await bootstrapClient.resolveConfigBlob(ipnsName);
            if (!resolved?.cid) return undefined;

            const encrypted = await bootstrapClient.downloadBytes(resolved.cid);
            const plaintext = await unwrapKey(encrypted, userPrivateKey);
            let config: ByoIpfsConfig;
            try {
              const json = new TextDecoder().decode(plaintext);
              config = JSON.parse(json) as ByoIpfsConfig;
            } finally {
              clearBytes(plaintext);
            }

            // Runtime validation: ensure the blob has a valid shape
            const validModes = ['cipherbox', 'external', 'dual'];
            if (!config.pinningMode || !validModes.includes(config.pinningMode)) {
              return undefined;
            }
            if (config.pinningMode !== 'cipherbox' && !config.externalProvider?.endpoint) {
              return undefined;
            }

            return {
              mode: config.pinningMode,
              externalProvider: config.externalProvider ?? undefined,
            };
          };

          try {
            const result = await Promise.race([
              inner(),
              new Promise<undefined>((resolve) =>
                setTimeout(() => resolve(undefined), BYO_LOAD_TIMEOUT_MS)
              ),
            ]);
            return result;
          } catch {
            // No BYO config or decryption failed -- default to cipherbox-only
            return undefined;
          }
        };

        // Initialize SDK client with decrypted vault keys
        const vaultState = useVaultStore.getState();
        const authState = useAuthStore.getState();
        if (
          vaultState.rootReadKey &&
          vaultState.rootWriteKey &&
          vaultState.rootIpnsKeypair &&
          vaultState.rootIpnsName
        ) {
          const apiUrl = import.meta.env.VITE_API_URL || window.location.origin + '/api';
          const getAccessToken = async () => {
            const state = useAuthStore.getState();
            return state.accessToken || '';
          };

          // Load BYO config and vault settings in parallel before initializing SDK client
          const [pinningConfig, vaultSettings] = await Promise.all([
            loadByoConfig(userKeypair.privateKey),
            loadVaultSettings(bootstrapClient, userKeypair.privateKey),
          ]);

          // Populate vault settings store
          useVaultSettingsStore.getState().setSettings(vaultSettings);

          // @cipherbox/api-client is configured in lib/api-config.ts at module load time.

          const sdkClient = initSdkClient({
            apiUrl,
            getAccessToken,
            vaultKeypair: {
              publicKey: userKeypair.publicKey,
              privateKey: userKeypair.privateKey,
            },
            rootIpnsName: vaultState.rootIpnsName,
            // rootReadKey maps to the SDK's rootFolderKey slot (read-body seal key);
            // rootWriteKey feeds ensureFolderLoaded's DFS write-chain recovery (68.1-01).
            rootFolderKey: vaultState.rootReadKey!,
            rootWriteKey: vaultState.rootWriteKey!,
            // Pass the root IPNS signing keypair so the client can self-bootstrap
            // and lazy-load folderTree from root (dissolves "Folder not loaded";
            // fixes bin restore after reload). Guaranteed non-null by the guard above.
            rootIpnsKeypair: vaultState.rootIpnsKeypair,
            teeKeys: authState.teeKeys ?? undefined,
            pinningConfig,
            // shareCallbacks (getCoveringShares/addShareKeys) removed: the SDK's
            // per-recipient key fan-out is dead code (D-03 already skips it at
            // upload time) and the web `addShareKeys` fan-out it called into is
            // deleted (SC#2 / D-12) — encrypted-key refs replace it.
            // Concrete web driver for the scope-exit rotation injection seam
            // (68-05): durable job checkpoint + D-02/D-03 progress badge +
            // D-09 multi-tab leader election (68-08).
            rotationCallbacks: buildRotationClientCallbacks(),
            // Durable ROT-07 anti-rollback gate (Gap 1 / SC#4): the IndexedDB-backed
            // rotationHighWater makes the SDK's reconcileFolderSequence enforceResolved
            // check live for every revocation-triggering mutation in this client.
            rotationHighWater,
          });

          // Subscribe folder store to SDK events
          useFolderStore.getState().subscribeToSdk(sdkClient);

          // Subscribe bin store to SDK events
          useBinStore.getState().subscribeToSdk(sdkClient);

          // D-11 opportunistic post-mutation owner-reconcile trigger: after the
          // client emits a mutation-complete event for a folder, fire-and-forget
          // a reconcile scoped to that folder alongside the eager login sweep
          // below. Best-effort/idempotent -- errors are captured inside
          // runOwnerReconcileForFolder and never thrown here.
          sdkClient.on((event) => {
            if (event.type === 'folder:updated') {
              void runOwnerReconcileForFolder(event.ipnsName).catch((error) => {
                logger.error('[Auth] Opportunistic owner-reconcile failed (non-blocking):', error);
              });
            }
          });
        }
      } finally {
        // Zero this throwaway client's defensive key copies (D-09). The
        // real sdkClient constructed above (if any) is an independent
        // instance and is unaffected by this destroy() call.
        bootstrapClient.destroy();
      }

      // Non-blocking device registry initialization (fire-and-forget)
      // Placed after vault load so registry failures never block login
      void (async () => {
        try {
          const deviceKeypair = await getOrCreateDeviceIdentity({
            mode: 'persisted',
            vaultPrivateKey: userKeypair.privateKey,
          });
          const deviceInfo = detectDeviceInfo();
          const ipHashHex = await computeIpHash('0.0.0.0');
          const result = await initializeOrSyncRegistry({
            userPrivateKey: userKeypair.privateKey,
            userPublicKey: userKeypair.publicKey,
            deviceKeypair,
            deviceInfo: { ...deviceInfo, ipHash: ipHashHex },
          });
          if (result) {
            useDeviceRegistryStore
              .getState()
              .setRegistry(result.registry, result.ipnsName, deviceKeypair.deviceId);
          }
        } catch (error) {
          logger.error('[Auth] Device registry init failed (non-blocking):', error);
        }
      })();

      // Non-blocking bin initialization (fire-and-forget)
      // SDK loadBin handles IPNS resolve, decrypt, and auto-repair if no record exists
      void (async () => {
        try {
          const { getSdkClient, hasSdkClient } = await import('../lib/sdk-provider');
          if (hasSdkClient()) {
            const binState = await getSdkClient().loadBin();
            // Populate Zustand store from SDK-returned state
            const binStore = useBinStore.getState();
            binStore.setBinIpnsName(binState.ipnsName);
            binStore.setEntries(binState.entries, binState.sequenceNumber);
          }
        } catch (error) {
          logger.error('[Auth] Bin initialization failed (non-blocking):', error);
        }
      })();

      // Non-blocking rotation-resume check (fire-and-forget, once per app-open).
      // Surfaces the 'resuming' badge (D-02/D-03) when a durable rotation job
      // checkpoint was left over from a previous session/reload.
      void resumeInterruptedRotation().catch((error) => {
        logger.error('[Auth] Rotation resume check failed (non-blocking):', error);
      });

      // Non-blocking owner-reconcile sweep (fire-and-forget, D-11 eager cadence)
      // Re-mints/deletes any sent grants left dangling by a write-recipient's
      // independent unlink+bin while this session was offline. Best-effort --
      // errors are captured inside triggerOwnerReconcileOnLogin and never
      // propagate here. The opportunistic post-mutation trigger is wired in 68-08.
      void triggerOwnerReconcileOnLogin().catch((error) => {
        logger.error('[Auth] Owner-reconcile eager sweep failed (non-blocking):', error);
      });

      // Vault settings (retention, delete behavior, versioning) are loaded above
      // in parallel with BYO config and populated into useVaultSettingsStore.
    };
    vaultInitPromise = doInit().finally(() => {
      vaultInitPromise = null;
    });
    return vaultInitPromise;
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
      // Note: this does NOT set isAuthenticated — we wait until vault + SDK
      // are fully initialized to prevent Login.tsx from redirecting to /files
      // before the SDK client is ready for file operations.
      setAccessToken(response.accessToken);

      // 4. Remember auth method for UX
      setLastAuthMethod(authMethod);

      // 5. Initialize or load vault + SDK client
      await initializeOrLoadVault();

      // 6. Now that vault keys are loaded and SDK is initialized,
      // mark the user as authenticated. This triggers Login.tsx → /files redirect.
      setAuthenticated();

      setFaroUser(publicKey);
    },
    [getPublicKeyHex, setAccessToken, setAuthenticated, setLastAuthMethod, initializeOrLoadVault]
  );

  /**
   * Complete the login flow after REQUIRED_SHARE is resolved.
   * Called after inputFactorKey() succeeds (from recovery phrase or cross-device approval).
   * Uses the stored pendingCipherboxJwt to call completeBackendAuth with the REAL publicKey
   * (since Core Kit is now LOGGED_IN), then navigates to /files.
   */
  const completeRequiredShare = useCallback(async (): Promise<void> => {
    // Read directly from Zustand store to get fresh values — this callback
    // may be called from useDeviceApproval's useAuth() instance, so we
    // can't rely on closure-captured selector values.
    const { pendingCipherboxJwt: jwt, pendingAuthMethod: method } = useAuthStore.getState();

    if (!jwt || !method) {
      throw new Error('No pending auth info for REQUIRED_SHARE completion');
    }

    // Core Kit should now be LOGGED_IN after inputFactorKey()
    // Complete backend auth with the REAL publicKey (replaces the placeholder session)
    await completeBackendAuth(method, jwt);

    // NOW sync Core Kit React state to LOGGED_IN.
    // We deliberately delayed this from inputFactorKey() to prevent the session
    // restoration effect from firing before backend auth completed.
    // At this point isAuthenticated is true (from completeBackendAuth -> setAuthenticated),
    // so the session restore guard (coreKitLoggedIn && !isAuthenticated) won't trigger.
    syncStatus();

    // Clear pending state
    setPendingAuth(null, null);

    // Navigate to files
    navigate('/files');
  }, [completeBackendAuth, syncStatus, setPendingAuth, navigate]);

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
          setPendingAuth(cipherboxJwt, 'google');

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

        // Navigation handled by Login.tsx redirect effect (isAuthenticated → /files)
      } catch (error) {
        logger.error('[useAuth] Google login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginGoogle, completeBackendAuth, setAccessToken, setUserEmail]
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
          setPendingAuth(cipherboxJwt, 'email');

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
        // Navigation handled by Login.tsx redirect effect (isAuthenticated → /files)
      } catch (error) {
        logger.error('[useAuth] Email login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginEmail, completeBackendAuth, setAccessToken, setUserEmail]
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
          setPendingAuth(cipherboxJwt, 'wallet');

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
        // Navigation is handled by Login.tsx's redirect effect (isAuthenticated → /files).
        // completeBackendAuth sets the access token early, but initializeOrLoadVault()
        // inside it may still be pending. An explicit navigate here would fire AFTER
        // vault init completes — by which point the user may have navigated away from
        // the login page, causing a disruptive late redirect.
      } catch (error) {
        logger.error('[useAuth] Wallet login failed:', error);
        throw error;
      } finally {
        setIsLoggingIn(false);
      }
    },
    [isLoggingIn, coreKitLoginWallet, completeBackendAuth, setAccessToken]
  );

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

      // 3. Clear all user-scoped stores (centralized helper)
      clearAllUserStores();

      clearFaroUser();

      // 4. Navigate to login
      navigate('/');
    } catch (error) {
      logger.error('[useAuth] Logout failed:', error);
      // Still clear state even if backend fails
      clearAllUserStores();
      clearFaroUser();
      navigate('/');
    } finally {
      setIsLoggingOut(false);
    }
  }, [accessToken, coreKitLogout, navigate, isLoggingOut]);

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

          // Load vault keys from Core Kit keypair + initialize SDK
          await initializeOrLoadVaultRef.current?.();

          // Mark as authenticated only after vault + SDK are ready
          setAuthenticated();

          const restoredKeypair = useAuthStore.getState().vaultKeypair;
          if (restoredKeypair?.publicKey?.length) {
            setFaroUser(bytesToHex(restoredKeypair.publicKey));
          }
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
  }, [
    coreKitLoggedIn,
    isAuthenticated,
    isLoggingIn,
    setAccessToken,
    setAuthenticated,
    setUserEmail,
  ]);

  return {
    isLoading,
    isAuthenticated,
    isRequiredShare,
    lastAuthMethod,
    userEmail,
    pendingAuthMethod,
    loginWithGoogle,
    loginWithEmail,
    loginWithWallet,
    completeRequiredShare,
    logout,
  };
}
