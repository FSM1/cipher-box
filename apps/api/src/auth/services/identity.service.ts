import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';

/**
 * secp256k1 identity-key operations for challenge-signature login.
 *
 * This is signature *verification* over server-issued challenges — the
 * server never receives private keys or any seed. Verification uses a
 * vetted library; no crypto primitive is implemented here.
 */
@Injectable()
export class IdentityService {
  /**
   * Normalize a hex-encoded secp256k1 public key (compressed or
   * uncompressed) to canonical form: compressed, lowercase hex. Accounts
   * are keyed by this canonical form so one key is one account regardless
   * of the encoding a client sends.
   */
  normalizePublicKey(publicKeyHex: string): string {
    try {
      return secp256k1.Point.fromHex(publicKeyHex.toLowerCase()).toHex(true);
    } catch {
      throw new BadRequestException('Invalid secp256k1 publicKey');
    }
  }

  /**
   * Verify a compact (64-byte, r||s hex) secp256k1 signature over
   * sha256(utf8(challenge)) against the identity publicKey.
   */
  verifyChallengeSignature(challenge: string, signatureHex: string, publicKeyHex: string): void {
    const messageHash = createHash('sha256').update(challenge, 'utf8').digest();
    let valid = false;
    try {
      valid = secp256k1.verify(
        Buffer.from(signatureHex, 'hex'),
        messageHash,
        Buffer.from(publicKeyHex, 'hex')
      );
    } catch {
      valid = false;
    }
    if (!valid) {
      throw new UnauthorizedException('Invalid challenge signature');
    }
  }

  /** SHA-256 hex digest of a canonical identifier for auth_methods lookup. */
  hashIdentifier(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /** Truncated publicKey for display: first 8 + last 6 hex chars. */
  truncatePublicKey(publicKeyHex: string): string {
    return `${publicKeyHex.slice(0, 8)}…${publicKeyHex.slice(-6)}`;
  }
}
