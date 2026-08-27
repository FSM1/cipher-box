import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHash } from 'node:crypto';
import { getAddress, verifyMessage } from 'viem';
import { parseSiweMessage, validateSiweMessage } from 'viem/siwe';

/**
 * The EIP-4361 `statement` each SIWE surface binds. One nonce pool serves
 * signing in and linking, so the statement is the only thing separating the two
 * intents: without it a signature phished under a sign-in prompt replays as a
 * link onto the attacker's account, and the unique `(kind, identifier_hash)`
 * index makes that permanent.
 */
export const SIWE_LOGIN_STATEMENT = 'Sign in to CipherBox encrypted storage';
export const SIWE_LINK_STATEMENT = 'Link wallet to CipherBox account';

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
   * Verify a SIWE message and signature against the expected nonce and the
   * intent the calling surface serves. Returns the EIP-55 checksummed wallet
   * address.
   */
  async verifySiweMessage(
    message: string,
    signature: `0x${string}`,
    expectedNonce: string,
    expectedStatement: string
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

    if (parsed.statement !== expectedStatement) {
      throw new UnauthorizedException('SIWE message states a different intent');
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
