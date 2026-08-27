import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { MetricsService } from '../ops/metrics.service';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { IdentityController } from './identity.controller';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { EmailOtpService } from './services/email-otp.service';
import { GoogleOAuthService } from './services/google-oauth.service';
import { IdentityExchangeService } from './services/identity-exchange.service';
import { IdentityService } from './services/identity.service';
import { IdentitySubjectService } from './services/identity-subject.service';
import { IdentityTokenService } from './services/identity-token.service';
import { MailProvider } from './services/mail.provider';
import { SIWE_LOGIN_STATEMENT, SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { AcceleratorToken } from './entities/accelerator-token.entity';
import { AcceleratorTokenService } from './services/accelerator-token.service';
import { TokenService } from './services/token.service';

/**
 * The identity exchange over HTTP against a REAL Postgres (ADR 0008 D1/D2):
 * every method mints a CipherBox token the JWKS verifies, the subject a
 * provider identity maps to is stable and unique, and none of it creates an
 * account — the account still materializes at `POST /auth/login`.
 */

const GOOGLE_CLIENT_ID = 'cipherbox.apps.googleusercontent.com';
const GOOGLE_ISSUER = 'https://accounts.google.com';

/** Captures delivered codes so a test can present the real one. */
class CapturingMailProvider extends MailProvider {
  delivered: { to: string; code: string }[] = [];

  sendVerificationCode(to: string, code: string): Promise<void> {
    this.delivered.push({ to, code });
    return Promise.resolve();
  }
}

describe('identity exchange HTTP flows (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let mail: CapturingMailProvider;
  let googleSigningKey: jose.CryptoKey;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    mail = new CapturingMailProvider();

    const google = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    googleSigningKey = google.privateKey;

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
        { provide: MailProvider, useValue: mail },
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
    mail.delivered = [];
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    await db.dataSource.query('TRUNCATE TABLE identity_subjects CASCADE');
  });

  const http = () => ctx.http;

  const userCount = () => db.dataSource.getRepository(User).count();
  const subjectCount = () => db.dataSource.getRepository(IdentitySubject).count();

  function googleIdToken(subject: string, email: string, audience = GOOGLE_CLIENT_ID) {
    return new jose.SignJWT({ email })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(subject)
      .setIssuer(GOOGLE_ISSUER)
      .setAudience(audience)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(googleSigningKey);
  }

  /** Signs a SIWE message against a freshly issued nonce, as the web app does. */
  async function walletSignature(privateKey: `0x${string}`) {
    const account = privateKeyToAccount(privateKey);
    const nonceRes = await request(http()).post('/auth/siwe/challenge').expect(200);
    const message = createSiweMessage({
      address: account.address,
      chainId: 1,
      domain: 'localhost:5173',
      nonce: nonceRes.body.nonce,
      uri: 'http://localhost:5173',
      version: '1',
      statement: SIWE_LOGIN_STATEMENT,
    });
    return { message, signature: await account.signMessage({ message }) };
  }

  /**
   * A fresh address per test. `EmailOtpService` caps sends per address over a
   * 15-minute window and holds that budget in memory for the app's whole life,
   * so tests sharing a literal address spend one budget between them.
   */
  const freshEmail = () => `member-${randomUUID()}@example.com`;

  async function emailGrant(address: string) {
    await request(http())
      .post('/auth/identity/email/send-code')
      .send({ email: address })
      .expect(200);
    const { code } = mail.delivered[mail.delivered.length - 1];
    return request(http())
      .post('/auth/identity/email/verify-code')
      .send({ email: address, code })
      .expect(200);
  }

  describe('JWKS', () => {
    it('serves the public half of the signing key and no private field', async () => {
      const res = await request(http()).get('/auth/.well-known/jwks.json').expect(200);

      expect(res.body.keys).toHaveLength(1);
      const [jwk] = res.body.keys;
      expect(jwk).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
      for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
        expect(jwk).not.toHaveProperty(secret);
      }
    });

    it('is not an auth attempt: a key refresh presents no credential', async () => {
      await request(http()).get('/auth/.well-known/jwks.json').expect(200);

      const scrape = await ctx.app.get(MetricsService).metricsText();
      expect(scrape).not.toMatch(/auth_attempts_total\{route="[^"]*jwks/);
    });

    it('verifies a minted token through the key set, and refuses one signed by anything else', async () => {
      const jwks = await request(http()).get('/auth/.well-known/jwks.json').expect(200);
      // Through the set rather than a hand-picked key: Web3Auth selects by
      // `kid`, so a header naming one the JWKS does not publish breaks real
      // verification while a key picked by index here still passes.
      const keys = jose.createLocalJWKSet(jwks.body as jose.JSONWebKeySet);

      const grant = await emailGrant(freshEmail());
      const { payload, protectedHeader } = await jose.jwtVerify(grant.body.token, keys, {
        issuer: 'cipherbox',
        audience: 'web3auth',
      });
      expect(protectedHeader.kid).toBe(jwks.body.keys[0].kid);
      expect(payload.sub).toBe(grant.body.verifierId);
      expect(payload.method).toBe('email');
      // Long enough for the Core Kit handshake, short enough that a leak is stale.
      expect(payload.exp! - payload.iat!).toBe(300);

      const unpublished = await new jose.SignJWT({ method: 'email' })
        .setProtectedHeader({ alg: 'RS256', kid: 'cipherbox-identity-does-not-exist' })
        .setSubject(payload.sub as string)
        .setIssuer('cipherbox')
        .setAudience('web3auth')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign((await jose.generateKeyPair('RS256', { modulusLength: 2048 })).privateKey);
      await expect(jose.jwtVerify(unpublished, keys)).rejects.toThrow(
        jose.errors.JWKSNoMatchingKey
      );

      const impostor = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
      const forged = await new jose.SignJWT({ method: 'email' })
        .setProtectedHeader({ alg: 'RS256', kid: protectedHeader.kid })
        .setSubject(payload.sub as string)
        .setIssuer('cipherbox')
        .setAudience('web3auth')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(impostor.privateKey);

      await expect(jose.jwtVerify(forged, keys)).rejects.toThrow(
        jose.errors.JWSSignatureVerificationFailed
      );
    });
  });

  describe('email', () => {
    it('signs a member in with a CipherBox-issued code', async () => {
      const address = freshEmail();
      const grant = await emailGrant(address);

      expect(mail.delivered[0].to).toBe(address);
      expect(mail.delivered[0].code).toMatch(/^[0-9]{6}$/);
      expect(grant.body.verifierId).toBeTruthy();
      expect(grant.body.email).toBe(address);
    });

    it('refuses a code CipherBox did not issue', async () => {
      const address = freshEmail();
      await request(http())
        .post('/auth/identity/email/send-code')
        .send({ email: address })
        .expect(200);
      const issued = mail.delivered[0].code;
      const forged = issued === '000000' ? '111111' : '000000';

      await request(http())
        .post('/auth/identity/email/verify-code')
        .send({ email: address, code: forged })
        .expect(401);
    });

    it('refuses a code for an address that never requested one', async () => {
      await request(http())
        .post('/auth/identity/email/verify-code')
        .send({ email: 'stranger@example.com', code: '123456' })
        .expect(401);
    });

    it('refuses to spend the same code twice', async () => {
      const address = freshEmail();
      await request(http())
        .post('/auth/identity/email/send-code')
        .send({ email: address })
        .expect(200);
      const { code } = mail.delivered[0];

      await request(http())
        .post('/auth/identity/email/verify-code')
        .send({ email: address, code })
        .expect(200);
      await request(http())
        .post('/auth/identity/email/verify-code')
        .send({ email: address, code })
        .expect(401);
    });

    it('reaches one subject from one address however it is spelled', async () => {
      const address = freshEmail();
      const first = await emailGrant(address);
      const second = await emailGrant(`  ${address.toUpperCase()}  `);

      expect(second.body.verifierId).toBe(first.body.verifierId);
      expect(await subjectCount()).toBe(1);
    });
  });

  describe('google', () => {
    it('mints a stable subject for one Google account', async () => {
      const first = await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'member@example.com') })
        .expect(200);
      const second = await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'member@example.com') })
        .expect(200);

      expect(second.body.verifierId).toBe(first.body.verifierId);
      expect(first.body.email).toBe('member@example.com');
      expect(await subjectCount()).toBe(1);
    });

    it('keys on the immutable Google subject, not the email', async () => {
      const before = await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'old@example.com') })
        .expect(200);
      const after = await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'new@example.com') })
        .expect(200);

      expect(after.body.verifierId).toBe(before.body.verifierId);
    });

    it('refuses a token minted for another OAuth client', async () => {
      await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'member@example.com', 'other') })
        .expect(401);
    });
  });

  describe('wallet', () => {
    it('mints a token whose subject is stable across repeat logins', async () => {
      const privateKey = generatePrivateKey();

      const first = await request(http())
        .post('/auth/identity/wallet')
        .send(await walletSignature(privateKey))
        .expect(200);
      const second = await request(http())
        .post('/auth/identity/wallet')
        .send(await walletSignature(privateKey))
        .expect(200);

      expect(first.body.verifierId).toBe(second.body.verifierId);
      expect(first.body.email).toBeNull();
      expect(await subjectCount()).toBe(1);
    });

    it('reaches a different subject for a different wallet', async () => {
      const first = await request(http())
        .post('/auth/identity/wallet')
        .send(await walletSignature(generatePrivateKey()))
        .expect(200);
      const second = await request(http())
        .post('/auth/identity/wallet')
        .send(await walletSignature(generatePrivateKey()))
        .expect(200);

      expect(first.body.verifierId).not.toBe(second.body.verifierId);
      expect(await subjectCount()).toBe(2);
    });

    it('refuses a replayed nonce', async () => {
      const signed = await walletSignature(generatePrivateKey());
      await request(http()).post('/auth/identity/wallet').send(signed).expect(200);
      await request(http()).post('/auth/identity/wallet').send(signed).expect(401);
    });

    it('refuses a signature from a different wallet than the message names', async () => {
      const { message } = await walletSignature(generatePrivateKey());
      const impostor = privateKeyToAccount(generatePrivateKey());

      await request(http())
        .post('/auth/identity/wallet')
        .send({ message, signature: await impostor.signMessage({ message }) })
        .expect(401);
    });
  });

  describe('the account model', () => {
    it('creates no account row, whichever method vouched', async () => {
      await emailGrant(freshEmail());
      await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', 'member@example.com') })
        .expect(200);
      await request(http())
        .post('/auth/identity/wallet')
        .send(await walletSignature(generatePrivateKey()))
        .expect(200);

      expect(await subjectCount()).toBe(3);
      expect(await userCount()).toBe(0);
    });

    it('does not cross-link methods that share an email', async () => {
      const shared = freshEmail();
      const viaEmail = await emailGrant(shared);
      const viaGoogle = await request(http())
        .post('/auth/identity/google')
        .send({ idToken: await googleIdToken('google-subject', shared) })
        .expect(200);

      expect(viaEmail.body.verifierId).not.toBe(viaGoogle.body.verifierId);
    });

    it('mints one subject when the same identity logs in concurrently', async () => {
      const idToken = await googleIdToken('google-subject', 'member@example.com');

      const responses = await Promise.all(
        Array.from({ length: 8 }, () =>
          request(http()).post('/auth/identity/google').send({ idToken }).expect(200)
        )
      );

      const distinct = new Set(responses.map((res) => res.body.verifierId));
      expect(distinct.size).toBe(1);
      expect(await subjectCount()).toBe(1);
    });
  });
});
