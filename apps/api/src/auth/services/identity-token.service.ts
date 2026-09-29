import { Injectable, OnModuleInit, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { createPublicKey } from 'node:crypto';
import { EntityManager } from 'typeorm';
import { Clock } from '../../common/clock';
import { Entropy } from '../../common/entropy';
import { UUID_RE } from '../../common/patterns';
import {
  IDENTITY_SUBJECT_KINDS,
  type IdentitySubjectKind,
} from '../entities/identity-subject.entity';
import { SpentIdentityToken } from '../entities/spent-identity-token.entity';

const KID = 'cipherbox-identity-1';
const ALGORITHM = 'RS256';

/** Who mints the token, and who is entitled to verify it. */
export const IDENTITY_TOKEN_ISSUER = 'cipherbox';
export const IDENTITY_TOKEN_AUDIENCE = 'web3auth';

/** Long enough for the Core Kit handshake, short enough that a leak is stale. */
const TOKEN_TTL_SECONDS = 300;

/** Expired rows one spend reclaims; each spend adds one row, so the table tracks its live set. */
const SPENT_SWEEP_BATCH = 100;

/**
 * How long past its token's expiry a spent row survives, so an instance whose
 * clock runs behind still finds the row for as long as it accepts the token.
 */
const SPENT_ROW_GRACE_MS = 60_000;

export interface IdentityTokenClaims {
  /** The `identity_subjects` row id — the Core Kit `verifierId`. */
  subject: string;
  method: IdentitySubjectKind;
}

export interface VerifiedIdentityToken extends IdentityTokenClaims {
  /** The token's `jti`, the key a spend records. */
  tokenId: string;
  expiresAt: Date;
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
    private readonly clock: Clock,
    private readonly entropy: Entropy
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
      .setJti(this.entropy.randomUuid())
      .setIssuer(IDENTITY_TOKEN_ISSUER)
      .setAudience(IDENTITY_TOKEN_AUDIENCE)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAt)
      .sign(this.signingKey);
    return { token, expiresAt: new Date(expiresAt * 1000) };
  }

  /**
   * Verify a token this API minted, and return its claims. Used where a caller
   * has no CipherBox session yet and an identity token is the only credential
   * it holds. Issuer and audience are pinned, so a token minted for some other
   * relying party cannot be replayed here.
   */
  async verify(token: string): Promise<VerifiedIdentityToken> {
    const { payload } = await jose.jwtVerify(
      token,
      await jose.importJWK(this.publicJwk, ALGORITHM),
      {
        issuer: IDENTITY_TOKEN_ISSUER,
        audience: IDENTITY_TOKEN_AUDIENCE,
        algorithms: [ALGORITHM],
        requiredClaims: ['exp', 'jti'],
        // Expiry reads the injected clock, the same seam `sign` stamps from.
        currentDate: this.clock.now(),
      }
    );
    const { sub: subject, method, jti: tokenId, exp } = payload;
    if (typeof subject !== 'string' || !isIdentitySubjectKind(method)) {
      throw new Error('identity token is missing its subject or method claim');
    }
    // `jose` accepts an `exp` such as `1e999` (Infinity) or `1e300`, which is no
    // valid instant for the spend row.
    const expiresAt = new Date((exp ?? NaN) * 1000);
    if (
      typeof tokenId !== 'string' ||
      !UUID_RE.test(tokenId) ||
      Number.isNaN(expiresAt.getTime())
    ) {
      throw new Error('identity token is missing its token id or a valid expiry');
    }
    return { subject, method, tokenId, expiresAt };
  }

  /**
   * Spend a verified token on the caller's transaction, so a registration the
   * caller then refuses rolls the spend back with it. The primary key makes a
   * concurrent spend of the same token wait for this one and then refuse.
   */
  async spend(manager: EntityManager, token: VerifiedIdentityToken): Promise<void> {
    const inserted = await manager
      .createQueryBuilder()
      .insert()
      .into(SpentIdentityToken)
      .values({ tokenId: token.tokenId, expiresAt: token.expiresAt })
      .orIgnore()
      .returning('token_id')
      .execute();
    if ((inserted.raw as unknown[]).length === 0) {
      throw new UnauthorizedException('Identity token already used');
    }
    // Swept after the insert, so a replay never pays for a sweep. `SKIP LOCKED`
    // yields rows a concurrent spend is already reclaiming.
    await manager.query(
      `DELETE FROM spent_identity_tokens WHERE ctid IN (
         SELECT ctid FROM spent_identity_tokens WHERE expires_at <= $1
         ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)`,
      [new Date(this.clock.now().getTime() - SPENT_ROW_GRACE_MS), SPENT_SWEEP_BATCH]
    );
  }

  /**
   * Derived from the public key rather than by stripping fields off the
   * private JWK, so no private field can reach the JWKS by omission.
   */
  private async exportPublicJwk(publicKey: jose.CryptoKey | jose.KeyObject): Promise<jose.JWK> {
    return { ...(await jose.exportJWK(publicKey)), kid: KID, alg: ALGORITHM, use: 'sig' };
  }
}

function isIdentitySubjectKind(value: unknown): value is IdentitySubjectKind {
  return typeof value === 'string' && IDENTITY_SUBJECT_KINDS.includes(value as IdentitySubjectKind);
}
