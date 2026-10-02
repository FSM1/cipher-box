import { ConfigService } from '@nestjs/config';
import * as jose from 'jose';
import { createHash, randomUUID } from 'node:crypto';
import request from 'supertest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { DeviceApprovalSessionController } from '../device-approval/device-approval-session.controller';
import { DeviceApprovalController } from '../device-approval/device-approval.controller';
import {
  approvalRequestPayload,
  deviceRegistrationPayload,
} from '../device-approval/device-signature';
import { DeviceController } from '../device-approval/device.controller';
import { AccountDevice } from '../device-approval/entities/account-device.entity';
import { DeviceApproval } from '../device-approval/entities/device-approval.entity';
import { AccountDeviceService } from '../device-approval/services/account-device.service';
import { DeviceApprovalService } from '../device-approval/services/device-approval.service';
import { MetricsService } from '../ops/metrics.service';
import {
  identityLogin,
  identityReproof,
  jwtPayload,
  link,
  siweLinkBody,
  siweSign,
} from '../testing/auth-http';
import { AUTH_SERVICE_ENTITIES, authServiceProviders } from '../testing/auth-providers';
import { createTestDeviceKey } from '../testing/device-keys';
import { CapturingMailProvider, fakeConfig } from '../testing/fakes';
import {
  createHttpIntegrationApp,
  HttpIntegrationApp,
  randomCompressedPublicKey,
} from '../testing/http-integration-app';
import { newIdentity, signChallenge, type TestIdentity } from '../testing/identities';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { IdentitySubject } from './entities/identity-subject.entity';
import { SpentIdentityToken } from './entities/spent-identity-token.entity';
import { IdentityController } from './identity.controller';
import { GoogleOAuthService } from './services/google-oauth.service';
import { IdentityExchangeService } from './services/identity-exchange.service';
import { IdentitySubjectService } from './services/identity-subject.service';
import { SIWE_LOGIN_STATEMENT } from './services/siwe.service';

/**
 * A linked login method opens the account it was linked to (ADR 0039 D1): the
 * link points the method's provider identity at the account's subject, so the
 * Core Kit derives the same key from it. Real Postgres, the real identity
 * exchange, and a real login that presents the identity token as the source of
 * the bound subject (ADR 0058 D2).
 */

const GOOGLE_CLIENT_ID = 'cipherbox.apps.googleusercontent.com';
const GOOGLE_ISSUER = 'https://accounts.google.com';

type LinkableKind = 'wallet' | 'email';
type Wallet = ReturnType<typeof privateKeyToAccount>;
type Account = { identity: TestIdentity; accessToken: string };

describe('method link HTTP flows (real Postgres)', () => {
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
      entities: [...AUTH_SERVICE_ENTITIES, SpentIdentityToken, AccountDevice, DeviceApproval],
      controllers: [
        AuthController,
        IdentityController,
        DeviceController,
        DeviceApprovalSessionController,
        DeviceApprovalController,
      ],
      providers: [
        MetricsService,
        ...authServiceProviders(mail),
        IdentityExchangeService,
        IdentitySubjectService,
        AccountDeviceService,
        DeviceApprovalService,
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
    await db.dataSource.query(
      'TRUNCATE TABLE users, identity_subjects, spent_identity_tokens, account_devices, device_approvals CASCADE'
    );
  });

  const http = () => ctx.http;

  function googleIdToken(subject: string, email: string) {
    return new jose.SignJWT({ email })
      .setProtectedHeader({ alg: 'RS256' })
      .setSubject(subject)
      .setIssuer(GOOGLE_ISSUER)
      .setAudience(GOOGLE_CLIENT_ID)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(googleSigningKey);
  }

  async function googleExchange(googleSubject: string, email: string) {
    const res = await request(http())
      .post('/auth/identity/google')
      .send({ idToken: await googleIdToken(googleSubject, email) })
      .expect(200);
    return { subject: res.body.verifierId as string, identityToken: res.body.token as string };
  }

  const loginAs = async (identity: TestIdentity, identityToken?: string) =>
    (await identityLogin(http(), identity, identityToken)).accessToken;

  function registerDevice(accessToken: string, identityToken: string) {
    const device = createTestDeviceKey();
    return request(http())
      .post('/devices')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({
        publicKey: device.publicKey,
        signature: device.sign(
          deviceRegistrationPayload(jwtPayload(accessToken).sub, device.publicKey)
        ),
        identityToken,
        label: 'browser',
      });
  }

  /** A Google sign-in whose login presented its token: subject S is bound, and no device exists. */
  async function googleAccount(email = `member-${randomUUID()}@example.com`) {
    const { subject, identityToken } = await googleExchange(`google-${randomUUID()}`, email);
    const identity = newIdentity();
    const accessToken = await loginAs(identity, identityToken);
    return { subject, identity, accessToken, email, identityToken };
  }

  async function linkWallet(account: Account, wallet: Wallet, expected: number) {
    const body = await siweLinkBody(http(), account.identity, account.accessToken, wallet);
    return link(http(), account.accessToken, body).expect(expected);
  }

  async function walletExchange(wallet: Wallet) {
    return request(http())
      .post('/auth/identity/wallet')
      .send(await siweSign(http(), wallet, SIWE_LOGIN_STATEMENT))
      .expect(200);
  }

  /** The account's display row of `kind`, by the id the settings pane would show. */
  async function methodId(accessToken: string, kind: LinkableKind): Promise<string> {
    const res = await request(http())
      .get('/auth/methods')
      .set('Authorization', `Bearer ${accessToken}`)
      .expect(200);
    return (res.body as { id: string; kind: string }[]).find((row) => row.kind === kind)!.id;
  }

  async function unlink(account: Account, kind: LinkableKind, expected: number) {
    const target = await methodId(account.accessToken, kind);
    const issued = await request(http())
      .post('/auth/challenge/step-up')
      .set('Authorization', `Bearer ${account.accessToken}`)
      .send({ operation: 'unlink', methodId: target })
      .expect(200);
    return request(http())
      .post('/auth/unlink')
      .set('Authorization', `Bearer ${account.accessToken}`)
      .send({
        methodId: target,
        challenge: issued.body.challenge,
        signature: signChallenge(issued.body.challenge, account.identity.privateKey),
      })
      .expect(expected);
  }

  const displayRows = (kind: LinkableKind) =>
    db.dataSource.getRepository(AuthMethod).count({ where: { kind } });
  const subjectRows = (kind: LinkableKind) =>
    db.dataSource.getRepository(IdentitySubject).count({ where: { kind } });

  describe('wallet link', () => {
    it('a linked wallet exchange reaches the subject of the account it was linked to', async () => {
      const account = await googleAccount();
      const wallet = privateKeyToAccount(generatePrivateKey());

      await linkWallet(account, wallet, 201);
      const signIn = await walletExchange(wallet);

      expect(signIn.body.verifierId).toBe(account.subject);
    });

    it('a linked wallet token opens a rendezvous for the account and registers a device under its subject', async () => {
      const account = await googleAccount();
      // The rendezvous also needs a registered device on the account (ADR 0039 D3).
      await registerDevice(account.accessToken, account.identityToken).expect(201);
      const wallet = privateKeyToAccount(generatePrivateKey());
      await linkWallet(account, wallet, 201);
      const identityToken = (await walletExchange(wallet)).body.token as string;

      const session = await request(http())
        .post('/device-approval/session')
        .send({ identityToken })
        .expect(200);
      const requester = createTestDeviceKey();
      const ephemeralPublicKey = randomCompressedPublicKey();
      await request(http())
        .post('/device-approval/requests')
        .set('Authorization', `Bearer ${session.body.accessToken}`)
        .send({
          devicePublicKey: requester.publicKey,
          ephemeralPublicKey,
          signature: requester.sign(
            approvalRequestPayload(requester.publicKey, ephemeralPublicKey)
          ),
        })
        .expect(201);
      await registerDevice(account.accessToken, identityToken).expect(201);

      const userId = jwtPayload(account.accessToken).sub;
      expect(jwtPayload(session.body.accessToken).sub).toBe(userId);
      const devices = await db.dataSource.getRepository(AccountDevice).find({ where: { userId } });
      expect(devices.map((device) => device.identitySubjectId)).toEqual([
        account.subject,
        account.subject,
      ]);
    });

    it('an unlinked wallet exchange mints a new subject', async () => {
      const account = await googleAccount();
      const wallet = privateKeyToAccount(generatePrivateKey());
      await linkWallet(account, wallet, 201);

      await unlink(account, 'wallet', 200);
      const signIn = await walletExchange(wallet);

      expect(signIn.body.verifierId).not.toBe(account.subject);
    });

    it('refuses an account that logged in without an identity token, and writes nothing', async () => {
      const identity = newIdentity();
      const account = { identity, accessToken: await loginAs(identity) };
      const wallet = privateKeyToAccount(generatePrivateKey());

      const refused = await linkWallet(account, wallet, 409);

      expect(refused.body.message).toBe('This account has no bound identity subject');
      expect(await displayRows('wallet')).toBe(0);
      expect(await subjectRows('wallet')).toBe(0);
    });

    it('refuses a wallet that already opens its own subject, and writes nothing', async () => {
      const account = await googleAccount();
      const wallet = privateKeyToAccount(generatePrivateKey());
      const own = await walletExchange(wallet);

      const refused = await linkWallet(account, wallet, 409);

      expect(refused.body.message).toBe('Wallet already opens another account');
      expect(await displayRows('wallet')).toBe(0);
      expect((await walletExchange(wallet)).body.verifierId).toBe(own.body.verifierId);
    });

    it('refuses the wallet the account was created through, and writes nothing', async () => {
      const wallet = privateKeyToAccount(generatePrivateKey());
      const first = await walletExchange(wallet);
      const identity = newIdentity();
      const account = { identity, accessToken: await loginAs(identity, first.body.token) };

      const refused = await linkWallet(account, wallet, 409);

      expect(refused.body.message).toBe('Wallet already opens this account');
      expect(await displayRows('wallet')).toBe(0);
      expect(await subjectRows('wallet')).toBe(1);
      expect((await walletExchange(wallet)).body.verifierId).toBe(first.body.verifierId);
    });
  });

  describe('the subject reference', () => {
    const subjects = () => db.dataSource.getRepository(IdentitySubject);
    const freshHash = () => createHash('sha256').update(randomUUID()).digest('hex');

    it('refuses a link row whose subject names no row', async () => {
      await expect(
        subjects().insert({ kind: 'wallet', identifierHash: freshHash(), subjectId: randomUUID() })
      ).rejects.toThrow(/fk_identity_subjects_subject/);
    });

    it('refuses to delete an origin row that a link row points at', async () => {
      const origin = randomUUID();
      await subjects().insert({
        id: origin,
        subjectId: origin,
        kind: 'google',
        identifierHash: freshHash(),
      });
      await subjects().insert({ kind: 'wallet', identifierHash: freshHash(), subjectId: origin });

      await expect(subjects().delete({ id: origin })).rejects.toThrow(
        /fk_identity_subjects_subject/
      );
      expect(await subjects().count({ where: { subjectId: origin } })).toBe(2);
    });
  });

  async function sendLinkCode(accessToken: string, email: string) {
    const res = await request(http())
      .post('/auth/email/link/send-code')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({ email })
      .expect(201);
    expect(res.text).toBe('');
    return mail.lastCode();
  }

  async function sendSignInCode(email: string) {
    await request(http()).post('/auth/identity/email/send-code').send({ email }).expect(200);
    return mail.lastCode();
  }

  async function linkEmail(account: Account, email: string, code: string, expected: number) {
    return request(http())
      .post('/auth/email/link')
      .set('Authorization', `Bearer ${account.accessToken}`)
      .send({
        email,
        code,
        ...(await identityReproof(http(), account.identity, account.accessToken)),
      })
      .expect(expected);
  }

  /** Request a link code for `email` under the account, then spend it on the link. */
  async function linkFreshCode(account: Account, email: string, expected: number) {
    return linkEmail(account, email, await sendLinkCode(account.accessToken, email), expected);
  }

  async function emailExchange(email: string) {
    const code = await sendSignInCode(email);
    return request(http())
      .post('/auth/identity/email/verify-code')
      .send({ email, code })
      .expect(200);
  }

  const freshEmail = () => `linked-${randomUUID()}@example.com`;

  describe('email link', () => {
    it('a linked address exchange reaches the subject of the account it was linked to', async () => {
      const account = await googleAccount();
      const email = freshEmail();

      const linked = await linkFreshCode(account, email, 201);
      const signIn = await emailExchange(email);

      expect(linked.text).toBe('');
      expect(signIn.body.verifierId).toBe(account.subject);
    });

    it('links the address of the Google account itself, and the address then opens that account', async () => {
      const account = await googleAccount();

      await linkFreshCode(account, account.email, 201);

      expect((await emailExchange(account.email)).body.verifierId).toBe(account.subject);
    });

    it('refuses a sign-in code at the link route, and writes nothing', async () => {
      const account = await googleAccount();
      const email = freshEmail();

      await linkEmail(account, email, await sendSignInCode(email), 401);

      expect(await displayRows('email')).toBe(0);
      expect(await subjectRows('email')).toBe(0);
    });

    it('refuses a link code another account requested, and writes nothing', async () => {
      const requester = await googleAccount();
      const other = await googleAccount();
      const email = freshEmail();
      const code = await sendLinkCode(requester.accessToken, email);

      const refused = await linkEmail(other, email, code, 401);

      expect(refused.body.message).toBe('No verification code is outstanding for this address');
      expect(await displayRows('email')).toBe(0);
      expect(await subjectRows('email')).toBe(0);
      await linkEmail(requester, email, code, 201);
    });

    it('refuses a link code at the sign-in route', async () => {
      const account = await googleAccount();
      const email = freshEmail();
      const code = await sendLinkCode(account.accessToken, email);

      await request(http())
        .post('/auth/identity/email/verify-code')
        .send({ email, code })
        .expect(401);
    });

    it('refuses a code send without a session', async () => {
      await request(http())
        .post('/auth/email/link/send-code')
        .send({ email: freshEmail() })
        .expect(401);
    });

    it('refuses an address that already opens its own subject, and writes nothing', async () => {
      const account = await googleAccount();
      const email = freshEmail();
      const own = await emailExchange(email);

      const refused = await linkFreshCode(account, email, 409);

      expect(refused.body.message).toBe('Email is already linked to another account');
      expect(await displayRows('email')).toBe(0);
      expect((await emailExchange(email)).body.verifierId).toBe(own.body.verifierId);
    });

    it('refuses an account that logged in without an identity token, and writes nothing', async () => {
      const identity = newIdentity();
      const account = { identity, accessToken: await loginAs(identity) };
      const email = freshEmail();

      const refused = await linkFreshCode(account, email, 409);

      expect(refused.body.message).toBe('This account has no bound identity subject');
      expect(await displayRows('email')).toBe(0);
      expect(await subjectRows('email')).toBe(0);
    });

    it('shows the address masked in the method list', async () => {
      const account = await googleAccount();
      const email = freshEmail();
      await linkFreshCode(account, email, 201);

      const res = await request(http())
        .get('/auth/methods')
        .set('Authorization', `Bearer ${account.accessToken}`)
        .expect(200);

      const row = (res.body as { kind: string; identifierDisplay: string }[]).find(
        (method) => method.kind === 'email'
      );
      expect(row?.identifierDisplay).toBe('l***@example.com');
    });

    it('an unlinked address exchange mints a new subject', async () => {
      const account = await googleAccount();
      const email = freshEmail();
      await linkFreshCode(account, email, 201);

      await unlink(account, 'email', 200);

      expect((await emailExchange(email)).body.verifierId).not.toBe(account.subject);
    });
  });
});
