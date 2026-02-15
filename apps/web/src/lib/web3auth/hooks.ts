import * as secp256k1 from '@noble/secp256k1';
import { hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { useCoreKit } from './core-kit-provider';
import { COREKIT_STATUS } from './core-kit';
import { authApi } from '../api/auth';

export function useCoreKitAuth() {
  const { coreKit, status, isLoggedIn, isInitialized } = useCoreKit();

  /**
   * Shared Core Kit login logic: takes a CipherBox JWT and userId,
   * calls loginWithJWT and commitChanges.
   */
  async function loginWithCoreKit(cipherboxJwt: string, userId: string): Promise<void> {
    if (!coreKit) throw new Error('Core Kit not initialized');

    // Login to Core Kit with CipherBox JWT
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const loginParams: any = {
      verifier: 'cipherbox-identity', // Single custom verifier for all CipherBox auth
      verifierId: userId,
      idToken: cipherboxJwt,
    };

    await coreKit.loginWithJWT(loginParams);

    // Handle status
    if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
      await coreKit.commitChanges();
    }
    // REQUIRED_SHARE means MFA is enabled but device factor missing
    // Phase 12.4 will handle this -- for now, throw so calling code can surface it
    if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
      throw new Error(
        'Additional verification required. Multi-factor recovery is not yet supported.'
      );
    }
  }

  /**
   * Login with Google: Backend verifies Google idToken, issues CipherBox JWT,
   * then we call loginWithJWT on Core Kit.
   *
   * @param googleIdToken - Google OAuth idToken from GIS callback
   */
  async function loginWithGoogle(
    googleIdToken: string
  ): Promise<{ cipherboxJwt: string; email?: string }> {
    // 1. Send Google idToken to CipherBox backend for verification + JWT issuance
    const { idToken: cipherboxJwt, userId, email } = await authApi.identityGoogle(googleIdToken);

    // 2. Login to Core Kit
    await loginWithCoreKit(cipherboxJwt, userId);

    return { cipherboxJwt, email };
  }

  /**
   * Login with Email: Backend handles OTP send/verify, issues CipherBox JWT.
   *
   * @param email - User's email address
   * @param otp - One-time password from email
   */
  async function loginWithEmailOtp(email: string, otp: string): Promise<{ cipherboxJwt: string }> {
    // 1. Verify OTP with backend, get CipherBox JWT
    const { idToken: cipherboxJwt, userId } = await authApi.identityEmailVerify(email, otp);

    // 2. Login to Core Kit
    await loginWithCoreKit(cipherboxJwt, userId);

    return { cipherboxJwt };
  }

  /**
   * Login with Wallet: Backend verifies SIWE signature, issues CipherBox JWT,
   * then we call loginWithJWT on Core Kit.
   *
   * @param cipherboxJwt - CipherBox identity JWT from wallet verification
   * @param userId - CipherBox user ID
   */
  async function loginWithWallet(
    cipherboxJwt: string,
    userId: string
  ): Promise<{ cipherboxJwt: string }> {
    // Login to Core Kit with the CipherBox JWT
    await loginWithCoreKit(cipherboxJwt, userId);

    return { cipherboxJwt };
  }

  /**
   * Get vault keypair from Core Kit's exported TSS key.
   * Replaces the PnP provider.request('private_key') approach.
   */
  async function getVaultKeypair(): Promise<{
    publicKey: Uint8Array;
    privateKey: Uint8Array;
  } | null> {
    if (!coreKit || coreKit.status !== COREKIT_STATUS.LOGGED_IN) return null;

    try {
      const privateKeyHex = await coreKit._UNSAFE_exportTssKey();
      const privKeyHex = privateKeyHex.startsWith('0x') ? privateKeyHex.slice(2) : privateKeyHex;
      const privateKey = hexToBytes(privKeyHex);
      const publicKey = secp256k1.getPublicKey(privateKey, false); // uncompressed (65 bytes)
      return { publicKey, privateKey };
    } catch (err) {
      console.error('[CoreKit] Failed to export TSS key:', err);
      return null;
    }
  }

  /**
   * Get compressed public key hex for backend auth.
   */
  async function getPublicKeyHex(): Promise<string | null> {
    const keypair = await getVaultKeypair();
    if (!keypair) return null;
    const compressed = secp256k1.getPublicKey(keypair.privateKey, true);
    return bytesToHex(compressed);
  }

  /**
   * Logout from Core Kit.
   */
  async function logout(): Promise<void> {
    if (!coreKit) return;
    try {
      if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
        await coreKit.logout();
      }
    } catch (err) {
      console.error('[CoreKit] Logout error:', err);
    }
  }

  return {
    status,
    isLoggedIn,
    isInitialized,
    loginWithGoogle,
    loginWithEmailOtp,
    loginWithWallet,
    getVaultKeypair,
    getPublicKeyHex,
    logout,
  };
}
