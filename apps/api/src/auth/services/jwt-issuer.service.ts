import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';

const KID = 'cipherbox-identity-1';
/** RSA private JWK fields to strip when creating the public JWK */
const RSA_PRIVATE_FIELDS = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi']);

@Injectable()
export class JwtIssuerService implements OnModuleInit {
  private readonly logger = new Logger(JwtIssuerService.name);
  private privateKey!: jose.CryptoKey | jose.KeyObject;
  private publicJwk!: jose.JWK;

  constructor(private config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const pemKey = this.config.get<string>('IDENTITY_JWT_PRIVATE_KEY');

    if (pemKey) {
      this.logger.log('Loading RS256 identity keypair from IDENTITY_JWT_PRIVATE_KEY env var');
      this.privateKey = await jose.importPKCS8(pemKey, 'RS256');
      // Derive public JWK from private key (strip private fields)
      const privateJwk = await jose.exportJWK(this.privateKey);
      const publicJwkData = Object.fromEntries(
        Object.entries(privateJwk).filter(([k]) => !RSA_PRIVATE_FIELDS.has(k))
      );
      this.publicJwk = { ...publicJwkData, kid: KID, alg: 'RS256', use: 'sig' };
    } else {
      this.logger.warn(
        'IDENTITY_JWT_PRIVATE_KEY not set — generating ephemeral RS256 keypair (dev/staging only)'
      );
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
      });
      this.privateKey = privateKey;
      const jwk = await jose.exportJWK(publicKey);
      this.publicJwk = { ...jwk, kid: KID, alg: 'RS256', use: 'sig' };
    }

    this.logger.log(`Identity JWKS ready (kid=${KID})`);
  }

  /**
   * Sign a CipherBox identity JWT for Web3Auth custom verifier consumption.
   *
   * Claims: iss=cipherbox, aud=web3auth, sub=userId, email (optional), exp=5min
   */
  async signIdentityJwt(userId: string, email?: string): Promise<string> {
    const claims: Record<string, unknown> = { sub: userId };
    if (email) {
      claims.email = email;
    }
    return new jose.SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid: KID })
      .setIssuer('cipherbox')
      .setAudience('web3auth')
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(this.privateKey);
  }

  /**
   * Return JWKS data for the /.well-known/jwks.json endpoint.
   */
  getJwksData(): { keys: jose.JWK[] } {
    return { keys: [this.publicJwk] };
  }
}
