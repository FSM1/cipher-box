/**
 * @cipherbox/crypto - Type Definitions
 *
 * Core types for cryptographic operations.
 */

/**
 * User's vault keypair for ECIES operations.
 * Source agnostic - same type whether derived from Web3Auth or external wallet (ADR-001).
 */
export type VaultKey = {
  /** 65-byte uncompressed secp256k1 public key */
  publicKey: Uint8Array;
  /** 32-byte secp256k1 private key */
  privateKey: Uint8Array;
};

/**
 * Result of AES-GCM encryption.
 * IV and ciphertext are kept separate for explicit handling.
 */
export type EncryptedData = {
  /** Encrypted data including authentication tag */
  ciphertext: Uint8Array;
  /** 12-byte initialization vector */
  iv: Uint8Array;
};

/**
 * Error codes for categorized error handling.
 * Generic messages are still used externally to prevent oracle attacks.
 */
export type CryptoErrorCode =
  | 'ENCRYPTION_FAILED'
  | 'DECRYPTION_FAILED'
  | 'KEY_WRAPPING_FAILED'
  | 'KEY_UNWRAPPING_FAILED'
  | 'INVALID_KEY_SIZE'
  | 'INVALID_IV_SIZE'
  | 'INVALID_PUBLIC_KEY_SIZE'
  | 'INVALID_PRIVATE_KEY_SIZE'
  | 'INVALID_SIGNATURE_SIZE'
  | 'SIGNING_FAILED'
  | 'RANDOM_GENERATION_FAILED'
  | 'SECURE_CONTEXT_REQUIRED';

/**
 * Custom error class for cryptographic operations.
 * Provides error codes for internal handling while keeping messages generic.
 */
export class CryptoError extends Error {
  readonly code: CryptoErrorCode;

  constructor(message: string, code: CryptoErrorCode) {
    super(message);
    this.name = 'CryptoError';
    this.code = code;

    // Maintain proper stack trace for V8 (Node.js-specific)
    const ErrorWithCapture = Error as typeof Error & {
      captureStackTrace?: (target: object, constructor: unknown) => void;
    };
    if (ErrorWithCapture.captureStackTrace) {
      ErrorWithCapture.captureStackTrace(this, CryptoError);
    }
  }
}
