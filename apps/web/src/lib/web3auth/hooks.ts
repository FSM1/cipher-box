import * as secp256k1 from '@noble/secp256k1';
import { useCoreKit } from './core-kit-provider';
import { COREKIT_STATUS } from './core-kit';
import { authApi } from '../api/auth';

export function useCoreKitAuth() {
  const { coreKit, status, isLoggedIn, isInitialized } = useCoreKit();

  /**
   * Login with Google: Backend verifies Google idToken, issues CipherBox JWT,
   * then we call loginWithJWT on Core Kit.
   */
  async function loginWithGoogle(googleIdToken: string): Promise<{ cipherboxJwt: string }> {
    if (!coreKit) throw new Error('Core Kit not initialized');

    // 1. Send Google idToken to CipherBox backend for verification + JWT issuance
    const { idToken: cipherboxJwt, userId } = await authApi.identityGoogle(googleIdToken);

    // 2. Login to Core Kit with CipherBox JWT
    // Web3Auth custom verifier name must match dashboard config
    await coreKit.loginWithJWT({
      verifier: 'cipherbox-identity', // Single custom verifier for all CipherBox auth
      verifierId: userId,
      idToken: cipherboxJwt,
    });

    // 3. Handle status
    if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
      await coreKit.commitChanges();
    }
    // REQUIRED_SHARE means MFA is enabled but device factor missing
    // Phase 12.4 will handle this -- for now, log a warning
    if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
      console.warn('[CoreKit] REQUIRED_SHARE status -- MFA challenge needed (not yet implemented)');
    }

    return { cipherboxJwt };
  }

  /**
   * Login with Email: Backend handles OTP send/verify, issues CipherBox JWT.
   */
  async function loginWithEmailOtp(email: string, otp: string): Promise<{ cipherboxJwt: string }> {
    if (!coreKit) throw new Error('Core Kit not initialized');

    // 1. Verify OTP with backend, get CipherBox JWT
    const { idToken: cipherboxJwt, userId } = await authApi.identityEmailVerify(email, otp);

    // 2. Login to Core Kit
    await coreKit.loginWithJWT({
      verifier: 'cipherbox-identity',
      verifierId: userId,
      idToken: cipherboxJwt,
    });

    if (coreKit.status === COREKIT_STATUS.LOGGED_IN) {
      await coreKit.commitChanges();
    }
    if (coreKit.status === COREKIT_STATUS.REQUIRED_SHARE) {
      console.warn('[CoreKit] REQUIRED_SHARE status -- MFA challenge needed (not yet implemented)');
    }

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
    getVaultKeypair,
    getPublicKeyHex,
    logout,
  };
}

// Utility functions
function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
