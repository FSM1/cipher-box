import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { DeviceApprovalSessionController } from '../device-approval/device-approval-session.controller';
import { AccountDevice } from '../device-approval/entities/account-device.entity';
import { DeviceApproval } from '../device-approval/entities/device-approval.entity';
import { AccountDeviceService } from '../device-approval/services/account-device.service';
import { DeviceApprovalService } from '../device-approval/services/device-approval.service';
import { MetricsService } from '../ops/metrics.service';
import { createTestDeviceKey } from '../testing/device-keys';
import { FakeClock, fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { newIdentity, signChallenge, type TestIdentity } from '../testing/identities';
import {
  bootedIdentityTokenService,
  encodedIdentitySigningKey,
  identityTokenWithJti,
} from '../testing/identity-tokens';
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
import { IdentityTokenService } from './services/identity-token.service';
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

describe('identity subject bind at login (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let googleSigningKey: jose.CryptoKey;
  /** The API's own identity-token key, so a test can mint what the API mints. */
  const identitySigningKey = encodedIdentitySigningKey();

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });

    const google = await jose.generateKeyPair('RS256', { modulusLength: 2048 });
    googleSigningKey = google.privateKey;

    const config = fakeConfig({
      NODE_ENV: 'test',
      GOOGLE_CLIENT_ID,
      IDENTITY_JWT_PRIVATE_KEY: identitySigningKey,
    });

    ctx = await createHttpIntegrationApp({
      db,
      withOps: false,
      entities: [
        User,
        AuthMethod,
        RefreshToken,
        AcceleratorToken,
        IdentitySubject,
        AccountDevice,
        DeviceApproval,
      ],
      controllers: [AuthController, IdentityController, DeviceApprovalSessionController],
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
        AccountDeviceService,
        DeviceApprovalService,
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
    await db.dataSource.query('TRUNCATE TABLE users, account_devices, device_approvals CASCADE');
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
    expect(res.body.expiresIn).toBe(300);
    return { token: res.body.token, subject: res.body.verifierId };
  }

  /** A challenge-signature login. Each call gets a fresh challenge. */
  async function login(identity: TestIdentity, status: number, identityToken?: string) {
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

  async function boundSubject(identity: TestIdentity): Promise<string | null | undefined> {
    const user = await db.dataSource
      .getRepository(User)
      .findOneBy({ publicKey: identity.publicKey });
    return user ? user.identitySubjectId : undefined;
  }

  async function accountId(identity: TestIdentity): Promise<string> {
    return (
      await db.dataSource.getRepository(User).findOneByOrFail({ publicKey: identity.publicKey })
    ).id;
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

  const apiNow = () => ctx.app.get(Clock).now();

  /** The claims this API stamps, signed with a key this API does not hold. */
  function forgedToken(): Promise<string> {
    return identityTokenWithJti(encodedIdentitySigningKey(), new FakeClock(apiNow()), randomUUID());
  }

  /** A token for `subject` that the API's own key signs, issued at `issuedAt`. */
  async function tokenIssuedAt(subject: string, issuedAt: Date): Promise<string> {
    const minter = await bootedIdentityTokenService(
      { NODE_ENV: 'test', IDENTITY_JWT_PRIVATE_KEY: identitySigningKey },
      new FakeClock(issuedAt)
    );
    return (await minter.sign({ subject, method: 'google' })).token;
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

  it('binds nothing when a device row from before the bind holds the subject for another account', async () => {
    const holder = newIdentity();
    await login(holder, 200);
    const { token, subject } = await exchange('google-a');
    const now = ctx.app.get(Clock).now();
    await db.dataSource.getRepository(AccountDevice).insert({
      userId: await accountId(holder),
      identitySubjectId: subject,
      publicKey: createTestDeviceKey().publicKey,
      label: null,
      createdAt: now,
      lastSeenAt: now,
    });
    const other = newIdentity();

    await login(other, 200, token);

    expect(await boundSubject(other)).toBeNull();
    expect(await boundSubject(holder)).toBeNull();
    await request(http())
      .post('/device-approval/session')
      .send({ identityToken: token })
      .expect(404);
  });

  describe('a bad identity token', () => {
    it('refuses a token this API did not mint, and creates no account', async () => {
      const res = await login(newIdentity(), 401, await forgedToken());

      expect(res.body.message).toBe('Invalid identity token');
      expect(await userCount()).toBe(0);
    });

    it('refuses a token that expired 1 s before the API clock, and creates no account', async () => {
      const { subject } = await exchange('google-a');
      // The lifetime is 300 s, so a token issued 301 s ago expired 1 s ago.
      const expired = await tokenIssuedAt(subject, new Date(apiNow().getTime() - 301_000));

      const res = await login(newIdentity(), 401, expired);

      expect(res.body.message).toBe('Invalid identity token');
      expect(await userCount()).toBe(0);
      expect(await accountsBoundTo(subject)).toBe(0);

      // The same key with a live token binds, so the refusal above is the expiry.
      const live = newIdentity();
      await login(live, 200, await tokenIssuedAt(subject, apiNow()));
      expect(await boundSubject(live)).toBe(subject);
    });

    it('refuses a string that is not a token, and creates no account', async () => {
      const res = await login(newIdentity(), 401, 'not-a-token');

      expect(res.body.message).toBe('Invalid identity token');
      expect(await userCount()).toBe(0);
    });
  });

  it('binds exactly one of two concurrent first logins that present one subject', async () => {
    const { token, subject } = await exchange('google-a');
    const first = newIdentity();
    const second = newIdentity();

    await Promise.all([login(first, 200, token), login(second, 200, token)]);

    const binds = [await boundSubject(first), await boundSubject(second)];
    expect(binds.filter((bind) => bind === subject)).toHaveLength(1);
    expect(binds.filter((bind) => bind === null)).toHaveLength(1);
    expect(await userCount()).toBe(2);
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
