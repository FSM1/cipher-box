import { Injectable, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { createPublicKey } from 'node:crypto';
import { Clock } from '../../common/clock';
import type { IdentitySubjectKind } from '../entities/identity-subject.entity';

const KID = 'cipherbox-identity-1';
const ALGORITHM = 'RS256';

/** Who mints the token, and who is entitled to verify it. */
export const IDENTITY_TOKEN_ISSUER = 'cipherbox';
export const IDENTITY_TOKEN_AUDIENCE = 'web3auth';

/** Long enough for the Core Kit handshake, short enough that a leak is stale. */
const TOKEN_TTL_SECONDS = 300;

export interface IdentityTokenClaims {
  /** The `identity_subjects` row id — the Core Kit `verifierId`. */
  subject: string;
  method: IdentitySubjectKind;
}

/**
 * Mints the identity token the Core Kit consumes, and serves the JWKS the
 * Web3Auth custom verifier fetches to check it (ADR 0008 D1).
 */
@Injectable()
export class IdentityTokenService implements OnModuleInit {
  private signingKey!: jose.CryptoKey | jose.KeyObject;
  private publicJwk!: jose.JWK;

  constructor(
    private readonly configService: ConfigService,
    private readonly clock: Clock
  ) {}

  async onModuleInit(): Promise<void> {
    const nodeEnv = this.configService.get<string>('NODE_ENV') ?? 'development';
    const encodedPem = this.configService.get<string>('IDENTITY_JWT_PRIVATE_KEY');

    if (encodedPem) {
      // Base64-encoded because a multiline PEM does not survive a .env file.
      const pem = Buffer.from(encodedPem, 'base64').toString('utf8');
      this.signingKey = await jose.importPKCS8(pem, ALGORITHM);
      this.publicJwk = await this.exportPublicJwk(createPublicKey(pem));
      return;
    }

    // Allowlisted exactly as `buildJwtOptions` allowlists the JWT secret, and
    // for a sharper reason: Torus caches the JWKS per URL, so a keypair
    // regenerated on restart makes every later login fail verification against
    // the cached public half — surfacing as `crypto/rsa: verification error`,
    // which names neither the key nor the restart.
    if (nodeEnv !== 'development' && nodeEnv !== 'test') {
      throw new Error(
        `IDENTITY_JWT_PRIVATE_KEY is required when NODE_ENV is '${nodeEnv}' — ` +
          'generate with: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 | base64 -w0'
      );
    }
    const { publicKey, privateKey } = await jose.generateKeyPair(ALGORITHM, {
      modulusLength: 2048,
    });
    this.signingKey = privateKey;
    this.publicJwk = await this.exportPublicJwk(publicKey);
  }

  /** The public half only; the JWKS is world-readable by design. */
  jwks(): { keys: jose.JWK[] } {
    return { keys: [this.publicJwk] };
  }

  /**
   * Sign an identity token for an already-verified provider identity. The
   * `method` claim rides along so a restored Core Kit session can still name
   * how it was established — `getUserInfo()` reflects the token's own claims.
   */
  async sign(claims: IdentityTokenClaims): Promise<{ token: string; expiresAt: Date }> {
    const issuedAt = Math.floor(this.clock.now().getTime() / 1000);
    const expiresAt = issuedAt + TOKEN_TTL_SECONDS;
    const token = await new jose.SignJWT({ method: claims.method })
      .setProtectedHeader({ alg: ALGORITHM, kid: KID })
      .setSubject(claims.subject)
      .setIssuer(IDENTITY_TOKEN_ISSUER)
      .setAudience(IDENTITY_TOKEN_AUDIENCE)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.signingKey);
    return { token, expiresAt: new Date(expiresAt * 1000) };
  }

  /**
   * Derived from the public key rather than by stripping fields off the
   * private JWK, so no private field can reach the JWKS by omission.
   */
  private async exportPublicJwk(publicKey: jose.CryptoKey | jose.KeyObject): Promise<jose.JWK> {
    return { ...(await jose.exportJWK(publicKey)), kid: KID, alg: ALGORITHM, use: 'sig' };
  }
}
