import { useCallback } from 'react';
import BN from 'bn.js';
import * as secp256k1 from '@noble/secp256k1';
import { hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { useCoreKit } from './core-kit-provider';
import { COREKIT_STATUS } from './core-kit';
import { authApi } from '../api/auth';
import { logger } from '../logger';

export type CoreKitLoginResult = 'logged_in' | 'required_share';

export function useCoreKitAuth() {
  const { coreKit, status, isLoggedIn, isInitialized, isRequiredShare, syncStatus } = useCoreKit();

  /**
   * Login with Google: Backend verifies Google idToken, issues CipherBox JWT,
   * then we call loginWithJWT on Core Kit.
   */
  const loginWithGoogle = useCallback(
    async (
      googleIdToken: string
    ): Promise<{
      cipherboxJwt: string;
      email?: string;
      userId: string;
      status: CoreKitLoginResult;
    }> => {
      if (!coreKit) throw new Error('Core Kit not initialized');

      const { idToken: cipherboxJwt, userId, email } = await authApi.identityGoogle(googleIdToken);
      const coreKitStatus = await doLoginWithCoreKit(coreKit, syncStatus, cipherboxJwt, userId);
      return { cipherboxJwt, email, userId, status: coreKitStatus };
    },
    [coreKit, syncStatus]
  );

  /**
   * Login with Email: Backend handles OTP send/verify, issues CipherBox JWT.
   */
  const loginWithEmailOtp = useCallback(
    async (
      email: string,
      otp: string
    ): Promise<{ cipherboxJwt: string; userId: string; status: CoreKitLoginResult }> => {
      if (!coreKit) throw new Error('Core Kit not initialized');

      const { idToken: cipherboxJwt, userId } = await authApi.identityEmailVerify(email, otp);
      const coreKitStatus = await doLoginWithCoreKit(coreKit, syncStatus, cipherboxJwt, userId);
      return { cipherboxJwt, userId, status: coreKitStatus };
    },
    [coreKit, syncStatus]
  );

  /**
   * Login with Wallet: Backend verifies SIWE signature, issues CipherBox JWT,
   * then we call loginWithJWT on Core Kit.
   */
  const loginWithWallet = useCallback(
    async (
      cipherboxJwt: string,
      userId: string
    ): Promise<{ cipherboxJwt: string; userId: string; status: CoreKitLoginResult }> => {
      if (!coreKit) throw new Error('Core Kit not initialized');

      const coreKitStatus = await doLoginWithCoreKit(coreKit, syncStatus, cipherboxJwt, userId);
      return { cipherboxJwt, userId, status: coreKitStatus };
    },
    [coreKit, syncStatus]
  );

  /**
   * Get vault keypair from Core Kit's exported TSS key.
   */
  const getVaultKeypair = useCallback(async (): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } | null> => {
    if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) return null;

    try {
      logger.debug('[CoreKit] _UNSAFE_exportTssKey starting...');
      console.time('[CoreKit] exportTssKey');
      const privateKeyHex = await coreKit._UNSAFE_exportTssKey();
      console.timeEnd('[CoreKit] exportTssKey');
      logger.debug('[CoreKit] exportTssKey done, hex length:', privateKeyHex.length);
      const privKeyHex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
      const privateKey = hexToBytes(privKeyHex);
      const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed (65 bytes)
      logger.debug('[CoreKit] keypair derived, pubkey hex length:', publicKey.length * 2);
      return { publicKey, privateKey };
    } catch (err) {
      console.timeEnd('[CoreKit] exportTssKey');
      logger.error('[CoreKit] Failed to export TSS key:', err);
      return null;
    }
  }, [coreKit]);

  /**
   * Get uncompressed public key hex for backend auth.
   */
  const getPublicKeyHex = useCallback(async (): Promise<string | null> => {
    const keypair = await getVaultKeypair();
    if (!keypair) return null;
    return bytesToHex(keypair.publicKey);
  }, [getVaultKeypair]);

  /**
   * Logout from Core Kit.
   */
  const logout = useCallback(async (): Promise<void> => {
    if (!coreKit) return;
    try {
      if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
        await coreKit.logout();
      }
    } catch (err) {
      logger.error('[CoreKit] Logout error:', err);
    } finally {
      syncStatus();
    }
  }, [coreKit, syncStatus]);

  return {
    status,
    isLoggedIn,
    isInitialized,
    isRequiredShare,
    loginWithGoogle,
    loginWithEmailOtp,
    loginWithWallet,
    getVaultKeypair,
    getPublicKeyHex,
    logout,
  };
}

/**
 * Shared Core Kit login logic extracted as a standalone function
 * (not a hook method) to avoid re-creation on every render.
 *
 * Takes a CipherBox JWT and userId, calls loginWithJWT and commitChanges.
 * Returns 'logged_in' if device factor found, 'required_share' if MFA
 * is enabled but this device lacks a factor.
 */
async function doLoginWithCoreKit(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  coreKit: any,
  syncStatus: () => void,
  cipherboxJwt: string,
  userId: string
): Promise<CoreKitLoginResult> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const loginParams: any = {
    verifier: 'cipherbox-identity',
    verifierId: userId,
    idToken: cipherboxJwt,
  };

  logger.debug('[CoreKit] loginWithJWT starting...', {
    verifier: loginParams.verifier,
  });
  console.time('[CoreKit] loginWithJWT');
  try {
    await coreKit.loginWithJWT(loginParams);
    console.timeEnd('[CoreKit] loginWithJWT');
    logger.debug('[CoreKit] loginWithJWT completed, status:', coreKit.status);
  } catch (err) {
    console.timeEnd('[CoreKit] loginWithJWT');
    logger.error('[CoreKit] loginWithJWT FAILED:', err);
    throw err;
  }

  // Handle status
  if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
    logger.debug('[CoreKit] commitChanges starting...');
    console.time('[CoreKit] commitChanges');
    try {
      await coreKit.commitChanges();
      console.timeEnd('[CoreKit] commitChanges');
      logger.debug('[CoreKit] commitChanges done');
    } catch (err) {
      console.timeEnd('[CoreKit] commitChanges');
      logger.error('[CoreKit] commitChanges FAILED:', err);
    }

    // DEBUG: Test exportTssKey in isolation BEFORE triggering React updates
    logger.debug('[CoreKit] DEBUG: testing exportTssKey in isolation...');
    console.time('[CoreKit] exportTssKey-test');
    try {
      const testKey = await coreKit._UNSAFE_exportTssKey();
      console.timeEnd('[CoreKit] exportTssKey-test');
      logger.debug('[CoreKit] exportTssKey-test succeeded, length:', testKey.length);
    } catch (err) {
      console.timeEnd('[CoreKit] exportTssKey-test');
      logger.error('[CoreKit] exportTssKey-test FAILED:', err);
    }

    logger.debug('[CoreKit] calling syncStatus...');
    syncStatus();
    logger.debug('[CoreKit] syncStatus called, returning logged_in');
    return 'logged_in';
  }

  if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
    // Bug fix: Web3Auth's handleExistingUser() does NOT auto-check localStorage
    // for the device factor when the hashedShare has been deleted (post-MFA).
    // We must manually retrieve and input the device factor if it exists.
    logger.debug('[CoreKit] REQUIRED_SHARE — checking for device factor in localStorage...');
    try {
      const deviceFactorHex = await coreKit.getDeviceFactor();
      if (deviceFactorHex) {
        logger.debug('[CoreKit] Device factor found in localStorage, auto-inputting...');
        await coreKit.inputFactorKey(new BN(deviceFactorHex, 'hex'));

        if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
          logger.debug('[CoreKit] Device factor accepted — now LOGGED_IN');
          try {
            await coreKit.commitChanges();
          } catch (err) {
            logger.error('[CoreKit] commitChanges after device factor FAILED:', err);
          }
          syncStatus();
          return 'logged_in';
        }
      } else {
        logger.debug('[CoreKit] No device factor in localStorage — true REQUIRED_SHARE');
      }
    } catch (err) {
      logger.warn('[CoreKit] Device factor check failed (expected on new device):', err);
    }

    syncStatus();
    return 'required_share';
  }

  throw new Error(`Unexpected Core Kit status: ${coreKit.status}`);
}
