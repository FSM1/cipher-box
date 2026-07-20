import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { getAddress, verifyMessage } from 'viem';
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe';

/**
 * SIWE (EIP-4361) verification for the secondary wallet auth method.
 * EOA-only, no RPC. Domains are validated against CORS_ALLOWED_ORIGINS.
 */
@Injectable()
export class SiweService {
  private readonly allowedDomains: string[];

  constructor(configService: ConfigService) {
    const rawOrigins = configService.get<string>('CORS_ALLOWED_ORIGINS');
    this.allowedDomains = rawOrigins
      ? rawOrigins
          .split(',')
          .map((origin) => origin.trim())
          .filter((origin) => !origin.includes('*'))
          .map((origin) => {
            try {
              return new URL(origin).host;
            } catch {
              return origin;
            }
          })
      : ['localhost:5173', 'localhost:4173', 'localhost'];
  }

  /**
   * Verify a SIWE message and signature against the expected nonce.
   * Returns the EIP-55 checksummed wallet address.
   */
  async verifySiweMessage(
    message: string,
    signature: `0x${string}`,
    expectedNonce: string
  ): Promise<string> {
    const parsed = parseSiweMessage(message);
    if (!parsed.address) {
      throw new UnauthorizedException('Invalid SIWE message: missing address');
    }

    const fieldsValid = this.allowedDomains.some((domain) =>
      validateSiweMessage({ message: parsed, domain, nonce: expectedNonce })
    );
    if (!fieldsValid) {
      throw new UnauthorizedException('SIWE message validation failed');
    }

    const signatureValid = await verifyMessage({ address: parsed.address, message, signature });
    if (!signatureValid) {
      throw new UnauthorizedException('Invalid SIWE signature');
    }

    return getAddress(parsed.address);
  }

  /** SHA-256 hex of the EIP-55 checksummed address; plaintext is never stored. */
  hashWalletAddress(address: string): string {
    return createHash('sha256').update(getAddress(address)).digest('hex');
  }

  /** Truncated address for display, e.g. "0xAbCd...1234". */
  truncateWalletAddress(address: string): string {
    const checksummed = getAddress(address);
    return `${checksummed.slice(0, 6)}...${checksummed.slice(-4)}`;
  }
}
