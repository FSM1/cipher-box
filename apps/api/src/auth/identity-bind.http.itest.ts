import { ConfigService } from '@nestjs/config';
import { secp256k1 } from '@noble/curves/secp256k1';
import * as jose from 'jose';
import { createHash, randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { MetricsService } from '../ops/metrics.service';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import { AuthController } from './auth.controller';
import { AcceleratorToken } from './entities/accelerator-token.entity';
import { AuthMethod } from './entities/auth-method.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityController } from './identity.controller';
import { AcceleratorTokenService } from './services/accelerator-token.service';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { EmailOtpService } from './services/email-otp.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { IdentityExchangeService } from './services/identity-exchange.service';
import { IdentityService } from './services/identity.service';
import { IdentitySubjectService } from './services/identity-subject.service';
import {
  IDENTITY_TOKEN_AUDIENCE,
  IDENTITY_TOKEN_ISSUER,
  IDENTITY_TOKEN_KID,
  IdentityTokenService,
} from './services/identity-token.service';
import { MailProvider } from './services/mail.provider';
import { SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

/**
 * The login bind over HTTP against a real Postgres (ADR 0058 D2). Each identity
 * token comes from a real Google exchange, so its subject row is real.
 */

const GOOGLE_CLIENT_ID = 'cipherbox.apps.googleusercontent.com';
const GOOGLE_ISSUER = 'https://accounts.google.com';

function newIdentity() {
  const privateKey = secp256k1.utils.randomPrivateKey();
  return {
    privateKey,
    publicKey: Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex'),
  };
}

type Identity = ReturnType<typeof newIdentity>;

function signChallenge(challenge: string, privateKey: Uint8Array): string {
  const hash = createHash('sha256').update(challenge, 'utf8').digest();
  return secp256k1.sign(hash, privateKey).toCompactHex();
}

describe('identity subject bind at login (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let googleSigningKey: jose.CryptoKey;
  let forgerySigningKey: jose.CryptoKey;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });

    const google = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    googleSigningKey = google.privateKey;
    forgerySigningKey = (await jose.generateKeyPair('RS256', { modulusLength: 2048 })).privateKey;

    const config = fakeConfig({ NODE_ENV: 'test', GOOGLE_CLIENT_ID });

    ctx = await createHttpIntegrationApp({
      db,
      withOps: false,
      entities: [User, AuthMethod, RefreshToken, AcceleratorToken, IdentitySubject],
      controllers: [AuthController, IdentityController],
      providers: [
        MetricsService,
        AuthMetricsInterceptor,
        AuthService,
        TestAuthService,
        TokenService,
        AcceleratorTokenService,
        ChallengeService,
        IdentityService,
        SiweService,
        JwtAuthGuard,
        IdentityExchangeService,
        IdentitySubjectService,
        IdentityTokenService,
        EmailOtpService,
        {
          provide: MailProvider,
          useValue: {
            sendVerificationCode: () => Promise.reject(new Error('no email in this suite')),
          },
        },
        {
          provide: GoogleOAuthService,
          useFactory: (configService: ConfigService) =>
            new GoogleOAuthService(configService, () => Promise.resolve(google.publicKey)),
          inject: [ConfigService],
        },
        { provide: Clock, useClass: SystemClock },
        { provide: Entropy, useClass: SystemEntropy },
        { provide: ConfigService, useValue: config.service },
      ],
    });
  });

  afterAll(async () => {
    await ctx?.close();
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    await db.dataSource.query('TRUNCATE TABLE identity_subjects CASCADE');
    await db.dataSource.query('TRUNCATE TABLE spent_identity_tokens');
  });

  const http = () => ctx.http;

  /** A real Google exchange. It returns the CipherBox identity token and its subject. */
  async function exchange(googleSubject: string): Promise<{ token: string; subject: string }> {
    const idToken = await new jose.SignJWT({ email: `${googleSubject}@example.com` })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(googleSubject)
      .setIssuer(GOOGLE_ISSUER)
      .setAudience(GOOGLE_CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(googleSigningKey);
    const res = await request(http()).post('/auth/identity/google').send({ idToken }).expect(200);
    return { token: res.body.token, subject: res.body.verifierId };
  }

  /** A challenge-signature login. Each call gets a fresh challenge. */
  async function login(identity: Identity, status: number, identityToken?: string) {
    const challengeRes = await request(http())
      .post('/auth/challenge')
      .send({ publicKey: identity.publicKey })
      .expect(200);
    const { challenge } = challengeRes.body;
    return request(http())
      .post('/auth/login')
      .send({
        publicKey: identity.publicKey,
        challenge,
        signature: signChallenge(challenge, identity.privateKey),
        ...(identityToken === undefined ? {} : { identityToken }),
      })
      .expect(status);
  }

  async function boundSubject(identity: Identity): Promise<string | null | undefined> {
    const user = await db.dataSource
      .getRepository(User)
      .findOneBy({ publicKey: identity.publicKey });
    return user ? user.identitySubjectId : undefined;
  }

  const userCount = () => db.dataSource.getRepository(User).count();

  async function accountsBoundTo(subject: string): Promise<number> {
    return db.dataSource.getRepository(User).countBy({ identitySubjectId: subject });
  }

  async function spentTokenCount(): Promise<number> {
    const [row] = await db.dataSource.query<{ count: number }[]>(
      'SELECT count(*)::int AS count FROM spent_identity_tokens'
    );
    return row.count;
  }

  /** The claims this API stamps, signed with a key this API does not hold. */
  function forgedToken(subject: string): Promise<string> {
    return new jose.SignJWT({ method: 'google' })
      .setProtectedHeader({ alg: 'RS256', kid: IDENTITY_TOKEN_KID })
      .setSubject(subject)
      .setJti(randomUUID())
      .setIssuer(IDENTITY_TOKEN_ISSUER)
      .setAudience(IDENTITY_TOKEN_AUDIENCE)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(forgerySigningKey);
  }

  it('binds a new account to the subject at the first login that presents a token', async () => {
    const identity = newIdentity();
    const { token, subject } = await exchange('google-a');

    const res = await login(identity, 200, token);

    expect(res.body.isNewUser).toBe(true);
    expect(await boundSubject(identity)).toBe(subject);
  });

  it('does not rebind a bound account to another subject', async () => {
    const identity = newIdentity();
    const first = await exchange('google-a');
    const second = await exchange('google-b');
    await login(identity, 200, first.token);

    const res = await login(identity, 200, second.token);

    expect(res.body.isNewUser).toBe(false);
    expect(await boundSubject(identity)).toBe(first.subject);
    expect(await accountsBoundTo(second.subject)).toBe(0);
  });

  it('accepts a login whose subject another account holds, and changes neither row', async () => {
    const holder = newIdentity();
    const other = newIdentity();
    const { token, subject } = await exchange('google-a');
    await login(holder, 200, token);

    const res = await login(other, 200, (await exchange('google-a')).token);

    expect(res.body.isNewUser).toBe(true);
    expect(await boundSubject(other)).toBeNull();
    expect(await boundSubject(holder)).toBe(subject);
    expect(await accountsBoundTo(subject)).toBe(1);
  });

  describe('a bad identity token', () => {
    it('refuses a token this API did not mint, and creates no account', async () => {
      const { subject } = await exchange('google-a');

      const res = await login(newIdentity(), 401, await forgedToken(subject));

      expect(res.body.message).toBe('Invalid identity token');
      expect(await userCount()).toBe(0);
    });

    it('refuses a string that is not a token, and creates no account', async () => {
      const res = await login(newIdentity(), 401, 'not-a-token');

      expect(res.body.message).toBe('Invalid identity token');
      expect(await userCount()).toBe(0);
    });
  });

  it('binds nothing at a login without a token', async () => {
    const identity = newIdentity();

    const res = await login(identity, 200);

    expect(res.body.isNewUser).toBe(true);
    expect(await boundSubject(identity)).toBeNull();
  });

  it('does not spend the token: the same token verifies at a second login', async () => {
    const identity = newIdentity();
    const { token, subject } = await exchange('google-a');

    await login(identity, 200, token);
    expect(await spentTokenCount()).toBe(0);

    await login(identity, 200, token);
    expect(await spentTokenCount()).toBe(0);
    expect(await boundSubject(identity)).toBe(subject);
  });
});
