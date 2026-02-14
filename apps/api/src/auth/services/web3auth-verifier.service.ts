import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jose from 'jose';

const JWKS_URL = 'https://api-auth.web3auth.io/jwks';

interface Web3AuthWallet {
  type: string;
  public_key?: string;
  address?: string;
  curve?: string;
}

interface Web3AuthPayload extends jose.JWTPayload {
  wallets?: Web3AuthWallet[];
  email?: string;
  name?: string;
  verifier?: string;
  verifierId?: string;
  aggregateVerifier?: string;
}

/**
 * Verifies Web3Auth-issued JWTs against the Web3Auth JWKS endpoint.
 * Used for verifying Core Kit session tokens when needed.
 * Note: Primary auth flow uses CipherBox-issued JWTs verified by JwtIssuerService.
 */
@Injectable()
export class Web3AuthVerifierService {
  private jwks: jose.JWTVerifyGetKey | null = null;

  private getJwks(): jose.JWTVerifyGetKey {
    if (!this.jwks) {
      this.jwks = jose.createRemoteJWKSet(new URL(JWKS_URL));
    }
    return this.jwks;
  }

  async verifyIdToken(idToken: string, expectedPublicKey: string): Promise<Web3AuthPayload> {
    const jwks = this.getJwks();

    let payload: Web3AuthPayload;
    try {
      const result = await jose.jwtVerify(idToken, jwks, {
        algorithms: ['ES256'],
      });
      payload = result.payload as Web3AuthPayload;
    } catch (error) {
      throw new UnauthorizedException(
        `Invalid Web3Auth token: ${error instanceof Error ? error.message : 'verification failed'}`
      );
    }

    // Verify secp256k1 public key matches
    const walletKey = payload.wallets?.find(
      (w) => w.type === 'web3auth_app_key' && w.curve === 'secp256k1'
    );
    if (!walletKey?.public_key) {
      throw new UnauthorizedException('No secp256k1 public key found in token');
    }
    if (walletKey.public_key !== expectedPublicKey) {
      throw new UnauthorizedException('Public key mismatch');
    }

    return payload;
  }

  extractIdentifier(payload: Web3AuthPayload): string {
    // Extract the most meaningful identifier from the payload
    if (payload.email) {
      return payload.email;
    }
    if (payload.verifierId) {
      return payload.verifierId;
    }
    // Fallback to wallet address or public key
    const wallet = payload.wallets?.[0];
    if (wallet?.address) {
      return wallet.address;
    }
    if (wallet?.public_key) {
      return wallet.public_key;
    }
    throw new UnauthorizedException('No identifier found in token');
  }

  extractAuthMethodType(
    payload: Web3AuthPayload
  ): 'google' | 'apple' | 'github' | 'email' | 'wallet' {
    // Detect auth method from verifier
    const verifier = payload.verifier?.toLowerCase() || '';
    const aggregateVerifier = payload.aggregateVerifier?.toLowerCase() || '';

    if (verifier.includes('google') || aggregateVerifier.includes('google')) {
      return 'google';
    }
    if (verifier.includes('apple') || aggregateVerifier.includes('apple')) {
      return 'apple';
    }
    if (verifier.includes('github') || aggregateVerifier.includes('github')) {
      return 'github';
    }
    if (
      verifier.includes('email') ||
      verifier.includes('passwordless') ||
      aggregateVerifier.includes('email')
    ) {
      return 'email';
    }

    // Default to email if email is present
    if (payload.email) {
      return 'email';
    }

    // Fallback
    return 'email';
  }
}
