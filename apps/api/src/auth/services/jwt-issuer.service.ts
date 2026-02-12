import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';

const KID = 'cipherbox-identity-1';

@Injectable()
export class JwtIssuerService implements OnModuleInit {
  private readonly logger = new Logger(JwtIssuerService.name);
  private privateKey!: jose.KeyLike;
  private publicKey!: jose.KeyLike;
  private publicJwk!: jose.JWK;

  constructor(private config: ConfigService) {}

  async onModuleInit(): Promise<void> {
    const pemKey = this.config.get<string>('IDENTITY_JWT_PRIVATE_KEY');

    if (pemKey) {
      this.logger.log('Loading RS256 identity keypair from IDENTITY_JWT_PRIVATE_KEY env var');
      this.privateKey = await jose.importPKCS8(pemKey, 'RS256');
      // Derive public key from private key by exporting and re-importing
      const privateJwk = await jose.exportJWK(this.privateKey);
      // Remove private fields to create public JWK
      const { d, p, q, dp, dq, qi, ...publicJwkData } = privateJwk;
      this.publicJwk = { ...publicJwkData, kid: KID, alg: 'RS256', use: 'sig' };
      this.publicKey = await jose.importJWK(this.publicJwk, 'RS256');
    } else {
      this.logger.warn(
        'IDENTITY_JWT_PRIVATE_KEY not set — generating ephemeral RS256 keypair (dev/staging only)',
      );
      const { publicKey, privateKey } = await jose.generateKeyPair('RS256', {
        modulusLength: 2048,
      });
      this.privateKey = privateKey;
      this.publicKey = publicKey;
      const jwk = await jose.exportJWK(publicKey);
      this.publicJwk = { ...jwk, kid: KID, alg: 'RS256', use: 'sig' };
    }

    this.logger.log(`Identity JWKS ready (kid=${KID})`);
  }

  /**
   * Sign a CipherBox identity JWT for Web3Auth custom verifier consumption.
   *
   * Claims: iss=cipherbox, aud=web3auth, sub=userId, exp=5min
   */
  async signIdentityJwt(userId: string): Promise<string> {
    return new jose.SignJWT({ sub: userId })
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
