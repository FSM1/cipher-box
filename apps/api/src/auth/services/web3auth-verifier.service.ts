import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as jose from 'jose';

const JWKS_ENDPOINTS = {
  social: 'https://api-auth.web3auth.io/jwks',
  external_wallet: 'https://authjs.web3auth.io/jwks',
} as const;

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

@Injectable()
export class Web3AuthVerifierService {
  private jwksCache: Map<string, jose.JWTVerifyGetKey> = new Map();

  private getJwks(loginType: 'social' | 'external_wallet'): jose.JWTVerifyGetKey {
    const url = JWKS_ENDPOINTS[loginType];
    if (!this.jwksCache.has(url)) {
      this.jwksCache.set(url, jose.createRemoteJWKSet(new URL(url)));
    }
    return this.jwksCache.get(url)!;
  }

  async verifyIdToken(
    idToken: string,
    expectedPublicKeyOrAddress: string,
    loginType: 'social' | 'external_wallet'
  ): Promise<Web3AuthPayload> {
    const jwks = this.getJwks(loginType);

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

    // Verify wallet/public key matches based on login type
    if (loginType === 'social') {
      const walletKey = payload.wallets?.find(
        (w) => w.type === 'web3auth_app_key' && w.curve === 'secp256k1'
      );
      if (!walletKey?.public_key) {
        throw new UnauthorizedException('No secp256k1 public key found in token');
      }
      if (walletKey.public_key !== expectedPublicKeyOrAddress) {
        throw new UnauthorizedException('Public key mismatch');
      }
    } else {
      const wallet = payload.wallets?.find((w) => w.type === 'ethereum');
      if (!wallet?.address) {
        throw new UnauthorizedException('No ethereum address found in token');
      }
      if (wallet.address.toLowerCase() !== expectedPublicKeyOrAddress.toLowerCase()) {
        throw new UnauthorizedException('Wallet address mismatch');
      }
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
    payload: Web3AuthPayload,
    loginType: 'social' | 'external_wallet'
  ): 'google' | 'apple' | 'github' | 'email' | 'wallet' {
    if (loginType === 'external_wallet') {
      return 'wallet';
    }

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
