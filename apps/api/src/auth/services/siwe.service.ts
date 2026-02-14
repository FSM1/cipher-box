import { Injectable, UnauthorizedException } from '@nestjs/common';
import { createHash, randomBytes } from 'crypto';
import { getAddress } from 'viem';
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe';
import { verifyMessage } from 'viem';

@Injectable()
export class SiweService {
  /**
   * Generate a cryptographically random nonce for SIWE.
   * Returns 32 hex characters (16 random bytes).
   * Exceeds EIP-4361 minimum of 8 alphanumeric characters.
   */
  generateNonce(): string {
    return randomBytes(16).toString('hex');
  }

  /**
   * Verify a SIWE message and signature (EOA only, no RPC needed).
   * Returns the verified wallet address (EIP-55 checksummed).
   *
   * @throws UnauthorizedException if message is invalid or signature doesn't match
   */
  async verifySiweMessage(
    message: string,
    signature: `0x${string}`,
    expectedNonce: string,
    expectedDomain: string
  ): Promise<string> {
    // 1. Parse the SIWE message
    const parsed = parseSiweMessage(message);
    if (!parsed.address) {
      throw new UnauthorizedException('Invalid SIWE message: missing address');
    }

    // 2. Validate message fields (domain, nonce, expiry, etc.)
    const isValid = validateSiweMessage({
      message: parsed,
      domain: expectedDomain,
      nonce: expectedNonce,
    });
    if (!isValid) {
      throw new UnauthorizedException('SIWE message validation failed');
    }

    // 3. Verify cryptographic signature (standalone utility, no RPC client needed)
    const signatureValid = await verifyMessage({
      address: parsed.address,
      message,
      signature,
    });
    if (!signatureValid) {
      throw new UnauthorizedException('Invalid SIWE signature');
    }

    // 4. Return checksummed address
    return getAddress(parsed.address);
  }

  /**
   * Hash a wallet address for database lookup.
   * Normalizes with EIP-55 checksum before hashing to ensure consistency
   * regardless of input casing.
   *
   * @returns SHA-256 hex digest of the checksummed address (64 chars)
   */
  hashWalletAddress(address: string): string {
    const checksummed = getAddress(address);
    return createHash('sha256').update(checksummed).digest('hex');
  }

  /**
   * Hash any identifier (email, Google sub, etc.) for database lookup.
   * The caller is responsible for normalization (e.g., lowercasing email).
   * Unlike hashWalletAddress, this does NOT apply EIP-55 checksumming.
   *
   * @returns SHA-256 hex digest of the value (64 chars)
   */
  hashIdentifier(value: string): string {
    return createHash('sha256').update(value).digest('hex');
  }

  /**
   * Truncate a wallet address for display purposes.
   * Returns first 6 + "..." + last 4 characters (e.g. "0xAbCd...1234").
   * The full plaintext address is NEVER stored in the database.
   */
  truncateWalletAddress(address: string): string {
    const checksummed = getAddress(address);
    return `${checksummed.slice(0, 6)}...${checksummed.slice(-4)}`;
  }
}
