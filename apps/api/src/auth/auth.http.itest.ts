import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import request from 'supertest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { authMethodLockKey } from '../common/advisory-lock';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import {
  createIntegrationDatabase,
  IntegrationDatabase,
  waitForAdvisoryLockWait,
} from '../testing/integration-db';
import { MetricsService } from '../ops/metrics.service';
import { AuthMetricsInterceptor } from './auth-metrics.interceptor';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { AcceleratorToken } from './entities/accelerator-token.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { GatewayController } from './gateway.controller';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthService } from './services/auth.service';
import { ChallengeService, type StepUpOperation } from './services/challenge.service';
import { AcceleratorTokenService } from './services/accelerator-token.service';
import { IdentityService } from './services/identity.service';
import { SIWE_LINK_STATEMENT, SIWE_LOGIN_STATEMENT, SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

/**
 * The auth HTTP flows re-homed onto a REAL Postgres: challenge-signature
 * login with implicit account creation, refresh-token rotation and the
 * reuse-kills-the-family invariant, SIWE link/login uniqueness, logout
 * revocation, and the staging-gated test-login — all against real
 * `users`/`auth_methods`/`refresh_tokens` rows, where the unique-constraint and
 * cascade behavior a fake repo could only approximate is genuine. The throttler
 * is off (`withOps: false`): these flows fire well past the auth surface's cap,
 * which is proven separately in the ops integration suite.
 */

function newIdentity() {
  const privateKey = secp256k1.utils.randomPrivateKey();
  return {
    privateKey,
    publicKeyCompressed: Buffer.from(secp256k1.getPublicKey(privateKey, true)).toString('hex'),
    publicKeyUncompressed: Buffer.from(secp256k1.getPublicKey(privateKey, false)).toString('hex'),
  };
}

function signChallenge(challenge: string, privateKey: Uint8Array): string {
  const hash = createHash('sha256').update(challenge, 'utf8').digest();
  return secp256k1.sign(hash, privateKey).toCompactHex();
}

function jwtPayload(token: string): { sub: string; publicKey: string } {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

describe('auth HTTP flows (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let configValues: Record<string, string | undefined>;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    const config = fakeConfig({ NODE_ENV: 'test', TEST_LOGIN_SECRET: 'e2e-secret' });
    configValues = config.values;

    ctx = await createHttpIntegrationApp({
      db,
      withOps: false,
      entities: [User, AuthMethod, RefreshToken, AcceleratorToken],
      controllers: [AuthController, GatewayController],
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
    configValues.NODE_ENV = 'test';
    configValues.TEST_LOGIN_SECRET = 'e2e-secret';
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  const http = () => ctx.http;

  async function usersWithKey(publicKey: string): Promise<number> {
    return db.dataSource.getRepository(User).count({ where: { publicKey } });
  }

  async function freshChallenge(identity: ReturnType<typeof newIdentity>): Promise<string> {
    const res = await request(http())
      .post('/auth/challenge')
      .send({ publicKey: identity.publicKeyCompressed })
      .expect(200);
    return res.body.challenge;
  }

  /** A step-up challenge, minted against the caller's own session. */
  function stepUpRequest(accessToken: string, body: Record<string, string>) {
    return request(http())
      .post('/auth/challenge/step-up')
      .set('Authorization', `Bearer ${accessToken}`)
      .send(body);
  }

  async function stepUpChallenge(
    accessToken: string,
    operation: StepUpOperation,
    methodId?: string
  ): Promise<string> {
    const body: Record<string, string> = { operation };
    if (methodId !== undefined) body.methodId = methodId;
    return (await stepUpRequest(accessToken, body).expect(200)).body.challenge;
  }

  /** The account key's answer to a fresh step-up challenge, as link and unlink demand. */
  async function identityReproof(
    identity: ReturnType<typeof newIdentity>,
    accessToken: string,
    operation: StepUpOperation = 'link',
    methodId?: string
  ): Promise<{ challenge: string; challengeSignature: string }> {
    const challenge = await stepUpChallenge(accessToken, operation, methodId);
    return { challenge, challengeSignature: signChallenge(challenge, identity.privateKey) };
  }

  async function identityLogin(identity = newIdentity()) {
    const challenge = await freshChallenge(identity);
    const loginRes = await request(http())
      .post('/auth/login')
      .send({
        publicKey: identity.publicKeyCompressed,
        challenge,
        signature: signChallenge(challenge, identity.privateKey),
      })
      .expect(200);
    return { identity, loginRes };
  }

  describe('challenge-signature login', () => {
    it('creates the account implicitly at first login and not at the second', async () => {
      const identity = newIdentity();
      const first = await identityLogin(identity);
      expect(first.loginRes.body.isNewUser).toBe(true);
      expect(first.loginRes.body.accessToken).toBeTruthy();
      expect(first.loginRes.body.refreshToken).toMatch(/^[0-9a-f]{64}$/);
      expect(first.loginRes.headers['set-cookie']?.[0]).toContain('refreshToken=');
      expect(first.loginRes.headers['set-cookie']?.[0]).toContain('HttpOnly');

      const second = await identityLogin(identity);
      expect(second.loginRes.body.isNewUser).toBe(false);
      expect(jwtPayload(second.loginRes.body.accessToken).sub).toBe(
        jwtPayload(first.loginRes.body.accessToken).sub
      );
      expect(await usersWithKey(identity.publicKeyCompressed)).toBe(1);
    });

    it('keys the account by the canonical compressed publicKey regardless of encoding', async () => {
      const identity = newIdentity();
      const challengeRes = await request(http())
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyUncompressed })
        .expect(200);
      await request(http())
        .post('/auth/login')
        .send({
          publicKey: identity.publicKeyUncompressed,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(challengeRes.body.challenge, identity.privateKey),
        })
        .expect(200);
      expect(await usersWithKey(identity.publicKeyCompressed)).toBe(1);
    });

    it('rejects a signature from the wrong key', async () => {
      const identity = newIdentity();
      const wrongKey = newIdentity();
      const challengeRes = await request(http())
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyCompressed })
        .expect(200);
      await request(http())
        .post('/auth/login')
        .send({
          publicKey: identity.publicKeyCompressed,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(challengeRes.body.challenge, wrongKey.privateKey),
        })
        .expect(401);
    });

    it('rejects challenge replay', async () => {
      const identity = newIdentity();
      const challengeRes = await request(http())
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyCompressed })
        .expect(200);
      const body = {
        publicKey: identity.publicKeyCompressed,
        challenge: challengeRes.body.challenge,
        signature: signChallenge(challengeRes.body.challenge, identity.privateKey),
      };
      await request(http()).post('/auth/login').send(body).expect(200);
      await request(http()).post('/auth/login').send(body).expect(401);
    });

    it('rejects a challenge issued to a different publicKey', async () => {
      const victim = newIdentity();
      const attacker = newIdentity();
      const challengeRes = await request(http())
        .post('/auth/challenge')
        .send({ publicKey: victim.publicKeyCompressed })
        .expect(200);
      await request(http())
        .post('/auth/login')
        .send({
          publicKey: attacker.publicKeyCompressed,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(challengeRes.body.challenge, attacker.privateKey),
        })
        .expect(401);
    });

    it('rejects malformed publicKeys and unexpected properties', async () => {
      await request(http()).post('/auth/challenge').send({ publicKey: 'not-hex' }).expect(400);
      await request(http())
        .post('/auth/challenge')
        .send({ publicKey: newIdentity().publicKeyCompressed, privateKey: 'never-send-this' })
        .expect(400);
    });
  });

  describe('refresh rotation', () => {
    it('rotates via body, and reuse of the old token kills the family', async () => {
      const { loginRes } = await identityLogin();
      const firstRefreshToken = loginRes.body.refreshToken;

      const rotated = await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: firstRefreshToken })
        .expect(200);
      expect(rotated.body.refreshToken).not.toBe(firstRefreshToken);

      // Reuse of the already-rotated token: 401 and the successor dies too.
      await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: firstRefreshToken })
        .expect(401);
      await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: rotated.body.refreshToken })
        .expect(401);
    });

    it('rotates via the HTTP-only cookie when the body is empty', async () => {
      const { loginRes } = await identityLogin();
      await request(http())
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${loginRes.body.refreshToken}`)
        .send({})
        .expect(200);
    });

    it('rejects a missing token', async () => {
      await request(http()).post('/auth/refresh').send({}).expect(401);
    });

    it('holds the cookie path to the same token shape as the body field', async () => {
      await request(http())
        .post('/auth/refresh')
        .set('Cookie', 'refreshToken=not-64-hex-chars')
        .send({})
        .expect(401);
    });
  });

  describe('read accelerator token', () => {
    const verify = (token?: string) => {
      const call = request(http()).get('/auth/gateway/verify');
      return token === undefined ? call : call.set('Authorization', `Bearer ${token}`);
    };

    it('mints a pseudonym at login that is neither the access nor the refresh token', async () => {
      const { loginRes } = await identityLogin();

      expect(loginRes.body.acceleratorToken).toMatch(/^[0-9a-f]{64}$/);
      expect(loginRes.body.acceleratorToken).not.toBe(loginRes.body.refreshToken);
      expect(loginRes.body.acceleratorToken).not.toBe(loginRes.body.accessToken);
      await verify(loginRes.body.acceleratorToken).expect(204);
    });

    it('refuses the session access token at the gateway leg', async () => {
      const { loginRes } = await identityLogin();
      await verify(loginRes.body.accessToken).expect(401);
    });

    it('refuses a missing, malformed, or unminted credential', async () => {
      await verify().expect(401);
      await request(http())
        .get('/auth/gateway/verify')
        .set('Authorization', 'a'.repeat(64))
        .expect(401);
      await verify('not-an-accelerator-token').expect(401);
      await verify('c'.repeat(64)).expect(401);
    });

    it('rotates on refresh, and the superseded pseudonym stops verifying', async () => {
      const { loginRes } = await identityLogin();
      const rotated = await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: loginRes.body.refreshToken })
        .expect(200);

      expect(rotated.body.acceleratorToken).not.toBe(loginRes.body.acceleratorToken);
      await verify(rotated.body.acceleratorToken).expect(204);
      await verify(loginRes.body.acceleratorToken).expect(401);
    });

    it('dies with the session at logout', async () => {
      const { loginRes } = await identityLogin();
      await request(http())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
        .expect(200);

      await verify(loginRes.body.acceleratorToken).expect(401);
    });

    it('dies with the family that reuse detection revokes', async () => {
      const { loginRes } = await identityLogin();
      const rotated = await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: loginRes.body.refreshToken })
        .expect(200);
      await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: loginRes.body.refreshToken })
        .expect(401);

      await verify(rotated.body.acceleratorToken).expect(401);
    });
  });

  describe('logout', () => {
    it('revokes every refresh token for the account', async () => {
      const { loginRes } = await identityLogin();
      await request(http())
        .post('/auth/logout')
        .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
        .expect(200);
      await request(http())
        .post('/auth/refresh')
        .send({ refreshToken: loginRes.body.refreshToken })
        .expect(401);
    });

    it('requires a valid access token', async () => {
      await request(http()).post('/auth/logout').expect(401);
      await request(http()).post('/auth/logout').set('Authorization', 'Bearer bogus').expect(401);
    });
  });

  /**
   * A nonce from the pool the intent names: the sign-in pool is
   * unauthenticated, the link pool is owner-authenticated and serves no other
   * route.
   */
  async function siweNonce(linkAccessToken?: string): Promise<string> {
    const pending = linkAccessToken
      ? request(http())
          .post('/auth/siwe/link-challenge')
          .set('Authorization', `Bearer ${linkAccessToken}`)
      : request(http()).post('/auth/siwe/challenge');
    return (await pending.send({}).expect(200)).body.nonce;
  }

  async function siweSign(
    account: ReturnType<typeof privateKeyToAccount>,
    statement: string,
    signer: ReturnType<typeof privateKeyToAccount> = account,
    linkAccessToken?: string
  ) {
    const message = createSiweMessage({
      address: account.address,
      chainId: 1,
      domain: 'localhost:5173',
      nonce: await siweNonce(linkAccessToken),
      uri: 'http://localhost:5173',
      version: '1',
      statement,
    });
    const signature = await signer.signMessage({ message });
    return { message, signature };
  }

  /** A complete `/auth/siwe/link` body: the SIWE pair plus the identity re-proof. */
  async function siweLinkBody(
    identity: ReturnType<typeof newIdentity>,
    accessToken: string,
    account: ReturnType<typeof privateKeyToAccount>,
    statement: string = SIWE_LINK_STATEMENT
  ) {
    const [siwe, reproof] = await Promise.all([
      siweSign(account, statement, account, accessToken),
      identityReproof(identity, accessToken),
    ]);
    return { ...siwe, ...reproof };
  }

  function link(accessToken: string, body: Record<string, string>) {
    return request(http())
      .post('/auth/siwe/link')
      .set('Authorization', `Bearer ${accessToken}`)
      .send(body);
  }

  /**
   * A challenge names the operation it authorises, so possession of a live
   * one buys exactly that operation. The mint that issues the two
   * account-management challenges is owner-authenticated, so an attacker
   * cannot mint one at all.
   */
  describe('operation-bound step-up challenges', () => {
    it.each(['link', 'unlink'] as const)(
      'refuses an unauthenticated %s mint',
      async (operation) => {
        await request(http()).post('/auth/challenge/step-up').send({ operation }).expect(401);
      }
    );

    it('refuses an unauthenticated SIWE link-nonce mint', async () => {
      await request(http()).post('/auth/siwe/link-challenge').send({}).expect(401);
    });

    it('refuses an operation it mints no pool for', async () => {
      const { loginRes } = await identityLogin();
      await stepUpRequest(loginRes.body.accessToken, { operation: 'login' }).expect(400);
    });

    /**
     * The signed bytes name the operation, never the row. An unlink therefore
     * names its row at the mint, and no other operation may name one.
     */
    it('refuses an unlink mint with no row, and a link mint that names one', async () => {
      const { loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      await stepUpRequest(accessToken, { operation: 'unlink' }).expect(400);
      await stepUpRequest(accessToken, {
        operation: 'link',
        methodId: '11111111-1111-4111-8111-111111111111',
      }).expect(400);
    });

    it('refuses a scoped token that carries no account key', async () => {
      const { identity, loginRes } = await identityLogin();
      const scoped = await ctx.app.get(JwtService).signAsync({
        sub: jwtPayload(loginRes.body.accessToken).sub,
        publicKey: identity.publicKeyCompressed,
        scope: 'device-approval',
      });
      const refused = await stepUpRequest(scoped, {
        operation: 'unlink',
        methodId: '11111111-1111-4111-8111-111111111111',
      }).expect(403);
      expect(refused.body.message).toBe('Insufficient token scope');
    });

    it('mints a distinct domain tag per operation, and never the login tag', async () => {
      const { loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      const tags = await Promise.all([
        stepUpChallenge(accessToken, 'link'),
        stepUpChallenge(accessToken, 'unlink', '11111111-1111-4111-8111-111111111111'),
      ]);
      expect(new Set(tags.map((tag) => tag.split(':')[0])).size).toBe(2);
      for (const tag of tags) {
        expect(tag.startsWith('cipherbox-login:')).toBe(false);
      }
    });

    it('refuses a step-up challenge at the login route', async () => {
      const { identity, loginRes } = await identityLogin();
      const challenge = await stepUpChallenge(
        loginRes.body.accessToken,
        'unlink',
        '11111111-1111-4111-8111-111111111111'
      );
      await request(http())
        .post('/auth/login')
        .send({
          publicKey: identity.publicKeyCompressed,
          challenge,
          signature: signChallenge(challenge, identity.privateKey),
        })
        .expect(401);
    });
  });

  describe('SIWE secondary auth', () => {
    it('refuses login for an unlinked wallet — no implicit creation through SIWE', async () => {
      const account = privateKeyToAccount(generatePrivateKey());
      const { message, signature } = await siweSign(account, SIWE_LOGIN_STATEMENT);
      await request(http()).post('/auth/siwe/login').send({ message, signature }).expect(401);
    });

    it('links a wallet to the authenticated account, then logs in with it', async () => {
      const { identity, loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());

      await link(
        loginRes.body.accessToken,
        await siweLinkBody(identity, loginRes.body.accessToken, account)
      ).expect(201);

      const login = await siweSign(account, SIWE_LOGIN_STATEMENT);
      const siweLoginRes = await request(http()).post('/auth/siwe/login').send(login).expect(200);
      expect(jwtPayload(siweLoginRes.body.accessToken).sub).toBe(
        jwtPayload(loginRes.body.accessToken).sub
      );
    });

    it('refuses to link a wallet already linked to another account', async () => {
      const first = await identityLogin();
      const second = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());

      await link(
        first.loginRes.body.accessToken,
        await siweLinkBody(first.identity, first.loginRes.body.accessToken, account)
      ).expect(201);
      await link(
        second.loginRes.body.accessToken,
        await siweLinkBody(second.identity, second.loginRes.body.accessToken, account)
      ).expect(409);
    });

    it('rejects a tampered SIWE signature', async () => {
      const account = privateKeyToAccount(generatePrivateKey());
      const other = privateKeyToAccount(generatePrivateKey());
      const { message, signature } = await siweSign(account, SIWE_LOGIN_STATEMENT, other);
      await request(http()).post('/auth/siwe/login').send({ message, signature }).expect(401);
    });

    /**
     * The phish R2 names: one unauthenticated nonce pool serves both surfaces,
     * so without the statement an ordinary sign-in prompt yields a signature the
     * attacker replays as a link onto their own account — permanently, because
     * `uq_auth_methods_kind_identifier` then denies the victim that wallet.
     */
    it('refuses a sign-in signature replayed as a link, and links nothing', async () => {
      const { identity, loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());
      const userId = jwtPayload(loginRes.body.accessToken).sub;

      await link(
        loginRes.body.accessToken,
        await siweLinkBody(identity, loginRes.body.accessToken, account, SIWE_LOGIN_STATEMENT)
      ).expect(401);

      expect(
        await db.dataSource.getRepository(AuthMethod).count({ where: { userId, kind: 'wallet' } })
      ).toBe(0);
    });

    it('refuses a link signature replayed as a sign-in', async () => {
      const { identity, loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());
      await link(
        loginRes.body.accessToken,
        await siweLinkBody(identity, loginRes.body.accessToken, account)
      ).expect(201);

      const replayed = await siweSign(account, SIWE_LINK_STATEMENT);
      await request(http()).post('/auth/siwe/login').send(replayed).expect(401);
    });

    it('refuses a link whose challenge was signed by another key, and links nothing', async () => {
      const { loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());
      const userId = jwtPayload(loginRes.body.accessToken).sub;

      await link(
        loginRes.body.accessToken,
        await siweLinkBody(newIdentity(), loginRes.body.accessToken, account)
      ).expect(401);

      expect(
        await db.dataSource.getRepository(AuthMethod).count({ where: { userId, kind: 'wallet' } })
      ).toBe(0);
    });

    it('refuses a link whose challenge was already spent', async () => {
      const { identity, loginRes } = await identityLogin();
      const first = privateKeyToAccount(generatePrivateKey());
      const body = await siweLinkBody(identity, loginRes.body.accessToken, first);
      await link(loginRes.body.accessToken, body).expect(201);

      const second = privateKeyToAccount(generatePrivateKey());
      await link(loginRes.body.accessToken, {
        ...body,
        ...(await siweSign(second, SIWE_LINK_STATEMENT)),
      }).expect(401);
    });

    /**
     * The structural half of the binding. Every message here carries the statement
     * the target route expects and a re-proof the account key really made, so
     * only the pool a challenge was minted from can refuse it.
     */
    it('refuses a sign-in nonce spent as a link, statement notwithstanding', async () => {
      const { identity, loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      const account = privateKeyToAccount(generatePrivateKey());
      const userId = jwtPayload(accessToken).sub;

      await link(accessToken, {
        // A sign-in nonce: `siweSign` with no bearer reaches the open pool.
        ...(await siweSign(account, SIWE_LINK_STATEMENT)),
        ...(await identityReproof(identity, accessToken)),
      }).expect(401);

      expect(
        await db.dataSource.getRepository(AuthMethod).count({ where: { userId, kind: 'wallet' } })
      ).toBe(0);
    });

    it('refuses a link nonce spent as a wallet sign-in', async () => {
      const { identity, loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      const account = privateKeyToAccount(generatePrivateKey());
      await link(accessToken, await siweLinkBody(identity, accessToken, account)).expect(201);

      const linkNonced = await siweSign(account, SIWE_LOGIN_STATEMENT, account, accessToken);
      await request(http()).post('/auth/siwe/login').send(linkNonced).expect(401);

      // The same wallet and statement over a sign-in nonce still signs in, so
      // the pool is what refused the first attempt.
      const loginNonced = await siweSign(account, SIWE_LOGIN_STATEMENT);
      await request(http()).post('/auth/siwe/login').send(loginNonced).expect(200);
    });

    it('refuses a link re-proved with a login challenge, and links nothing', async () => {
      const { identity, loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      const account = privateKeyToAccount(generatePrivateKey());
      const userId = jwtPayload(accessToken).sub;
      const challenge = await freshChallenge(identity);

      await link(accessToken, {
        ...(await siweSign(account, SIWE_LINK_STATEMENT, account, accessToken)),
        challenge,
        challengeSignature: signChallenge(challenge, identity.privateKey),
      }).expect(401);

      expect(
        await db.dataSource.getRepository(AuthMethod).count({ where: { userId, kind: 'wallet' } })
      ).toBe(0);
    });

    it('refuses a scoped token on the link route', async () => {
      const { identity, loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());
      const scoped = await ctx.app.get(JwtService).signAsync({
        sub: jwtPayload(loginRes.body.accessToken).sub,
        publicKey: identity.publicKeyCompressed,
        scope: 'device-approval',
      });

      const refused = await link(
        scoped,
        await siweLinkBody(identity, loginRes.body.accessToken, account)
      ).expect(403);
      expect(refused.body.message).toBe('Insufficient token scope');
    });
  });

  describe('staging-gated test-login', () => {
    it('is hard-blocked in production regardless of the secret', async () => {
      configValues.NODE_ENV = 'production';
      await request(http())
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(403);
    });

    it('is disabled when TEST_LOGIN_SECRET is unset', async () => {
      configValues.TEST_LOGIN_SECRET = undefined;
      await request(http())
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'anything' })
        .expect(403);
    });

    it('rejects a wrong secret', async () => {
      await request(http())
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'wrong' })
        .expect(401);
    });

    it('logs in deterministically with the right secret', async () => {
      const first = await request(http())
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(200);
      expect(first.body.isNewUser).toBe(true);
      expect(first.body.publicKey).toMatch(/^(02|03)[0-9a-f]{64}$/);
      expect(first.body.privateKey).toMatch(/^[0-9a-f]{64}$/);

      const second = await request(http())
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(200);
      expect(second.body.isNewUser).toBe(false);
      expect(second.body.publicKey).toBe(first.body.publicKey);
    });

    it('yields an identity that can also log in via challenge-signature', async () => {
      const testRes = await request(http())
        .post('/auth/test-login')
        .send({ handle: 'crossover@test.local', secret: 'e2e-secret' })
        .expect(200);

      const challengeRes = await request(http())
        .post('/auth/challenge')
        .send({ publicKey: testRes.body.publicKey })
        .expect(200);
      const loginRes = await request(http())
        .post('/auth/login')
        .send({
          publicKey: testRes.body.publicKey,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(
            challengeRes.body.challenge,
            Buffer.from(testRes.body.privateKey, 'hex')
          ),
        })
        .expect(200);
      expect(loginRes.body.isNewUser).toBe(false);
    });
  });

  describe('login methods', () => {
    const authMethods = () => db.dataSource.getRepository(AuthMethod);

    /** An account whose identity method is joined by a linked wallet. */
    async function accountWithTwoMethods() {
      const { identity, loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      const wallet = privateKeyToAccount(generatePrivateKey());
      await link(accessToken, await siweLinkBody(identity, accessToken, wallet)).expect(201);
      return { identity, accessToken, userId: jwtPayload(accessToken).sub };
    }

    /**
     * An account left holding only wallet rows. No route reaches this state —
     * every login path plants a row unlink refuses to remove — so the count
     * guard, which is what makes the unlink transaction take the account lock,
     * can only be exercised from a state arranged out of band.
     */
    async function accountWithWalletsOnly(wallets: number) {
      const { identity, loginRes } = await identityLogin();
      const accessToken = loginRes.body.accessToken as string;
      for (let i = 0; i < wallets; i += 1) {
        const wallet = privateKeyToAccount(generatePrivateKey());
        await link(accessToken, await siweLinkBody(identity, accessToken, wallet)).expect(201);
      }
      const userId = jwtPayload(accessToken).sub;
      await authMethods().delete({ userId, kind: 'identity' });
      return { identity, accessToken, userId };
    }

    function listMethods(accessToken: string) {
      return request(http()).get('/auth/methods').set('Authorization', `Bearer ${accessToken}`);
    }

    function unlink(accessToken: string, body: Record<string, string>) {
      return request(http())
        .post('/auth/unlink')
        .set('Authorization', `Bearer ${accessToken}`)
        .send(body);
    }

    async function signedUnlink(
      identity: ReturnType<typeof newIdentity>,
      accessToken: string,
      methodId: string
    ): Promise<Record<string, string>> {
      const challenge = await stepUpChallenge(accessToken, 'unlink', methodId);
      return { methodId, challenge, signature: signChallenge(challenge, identity.privateKey) };
    }

    it('lists only the caller rows, in display form, never the identifier hash', async () => {
      const mine = await accountWithTwoMethods();
      const theirs = await accountWithTwoMethods();

      const res = await listMethods(mine.accessToken).expect(200);

      expect(res.body).toHaveLength(2);
      expect(res.body.map((row: { kind: string }) => row.kind).sort()).toEqual([
        'identity',
        'wallet',
      ]);
      for (const row of res.body) {
        expect(Object.keys(row).sort()).toEqual([
          'createdAt',
          'id',
          'identifierDisplay',
          'kind',
          'lastUsedAt',
        ]);
      }
      // Newest-created first.
      expect(res.body[0].kind).toBe('wallet');

      const mineIds = (await authMethods().find({ where: { userId: mine.userId } })).map(
        (row) => row.id
      );
      expect(res.body.map((row: { id: string }) => row.id).sort()).toEqual(mineIds.sort());

      // No stored hash may appear in any response — the caller's or anyone's.
      const stored = await authMethods().find();
      expect(stored).toHaveLength(4);
      const serialized = JSON.stringify(res.body);
      for (const row of stored) {
        expect(serialized).not.toContain(row.identifierHash);
      }
      expect(serialized).not.toContain('identifierHash');

      const theirsRes = await listMethods(theirs.accessToken).expect(200);
      expect(theirsRes.body.map((row: { id: string }) => row.id).sort()).not.toEqual(
        mineIds.sort()
      );
    });

    it('unlinks a method the caller owns once the identity key is re-proved', async () => {
      const { identity, accessToken, userId } = await accountWithTwoMethods();
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;

      const res = await unlink(
        accessToken,
        await signedUnlink(identity, accessToken, wallet)
      ).expect(200);
      expect(res.body).toEqual({ success: true });
      expect(await authMethods().count({ where: { userId } })).toBe(1);
    });

    it.each(['link', 'login'] as const)(
      'refuses an unlink re-proved with a %s challenge, and keeps the row',
      async (source) => {
        const { identity, accessToken, userId } = await accountWithTwoMethods();
        const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } }))
          .id;
        const challenge =
          source === 'login'
            ? await freshChallenge(identity)
            : await stepUpChallenge(accessToken, 'link');

        await unlink(accessToken, {
          methodId: wallet,
          challenge,
          signature: signChallenge(challenge, identity.privateKey),
        }).expect(401);

        expect(await authMethods().count({ where: { userId } })).toBe(2);
      }
    );

    /**
     * A stolen bearer plus one captured proof must not choose a different row:
     * the mint names the row, so the proof buys that removal and no other.
     */
    it('refuses an unlink redirected onto another row, and keeps both', async () => {
      const { identity, accessToken, userId } = await accountWithWalletsOnly(2);
      const rows = await authMethods().find({ where: { userId } });
      const challenge = await stepUpChallenge(accessToken, 'unlink', rows[0].id);

      await unlink(accessToken, {
        methodId: rows[1].id,
        challenge,
        signature: signChallenge(challenge, identity.privateKey),
      }).expect(401);

      expect(await authMethods().count({ where: { userId } })).toBe(2);
    });

    it('refuses to unlink the last remaining method and keeps the row', async () => {
      const { identity, accessToken, userId } = await accountWithWalletsOnly(1);
      const only = (await authMethods().findOneOrFail({ where: { userId } })).id;

      const res = await unlink(accessToken, await signedUnlink(identity, accessToken, only)).expect(
        409
      );
      expect(res.body.message).toBe('An account must keep at least one login method');
      expect(await authMethods().count({ where: { userId } })).toBe(1);
    });

    /**
     * `identityLogin` and `testLogin` authorise off the `users` table and then
     * re-insert their row, so deleting one revokes nothing: the next login
     * through that path recreates it. Refusing is the honest answer.
     */
    it.each(['identity', 'test'] as const)(
      'refuses to unlink a %s method even when another remains',
      async (kind) => {
        const { identity, accessToken, userId } = await accountWithTwoMethods();
        if (kind === 'test') {
          await authMethods().update({ userId, kind: 'identity' }, { kind: 'test' });
        }
        const target = (await authMethods().findOneOrFail({ where: { userId, kind } })).id;

        const res = await unlink(
          accessToken,
          await signedUnlink(identity, accessToken, target)
        ).expect(409);
        expect(res.body.message).toContain('cannot be unlinked');
        expect(await authMethods().count({ where: { userId } })).toBe(2);
      }
    );

    it('refuses a replayed challenge and keeps the row', async () => {
      const { identity, accessToken, userId } = await accountWithWalletsOnly(2);
      const methods = await authMethods().find({ where: { userId } });
      const body = await signedUnlink(identity, accessToken, methods[0].id);

      await unlink(accessToken, body).expect(200);
      // The same challenge again, now aimed at the survivor.
      await unlink(accessToken, { ...body, methodId: methods[1].id }).expect(401);
      expect(await authMethods().count({ where: { userId } })).toBe(1);
    });

    it('refuses a challenge issued to a different key', async () => {
      const { accessToken, userId } = await accountWithTwoMethods();
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;
      const stranger = newIdentity();

      const challenge = await freshChallenge(stranger);
      await unlink(accessToken, {
        methodId: wallet,
        challenge,
        signature: signChallenge(challenge, stranger.privateKey),
      }).expect(401);
      expect(await authMethods().count({ where: { userId } })).toBe(2);
    });

    it('refuses a signature from the wrong key', async () => {
      const { identity, accessToken, userId } = await accountWithTwoMethods();
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;

      const challenge = await freshChallenge(identity);
      await unlink(accessToken, {
        methodId: wallet,
        challenge,
        signature: signChallenge(challenge, newIdentity().privateKey),
      }).expect(401);
      expect(await authMethods().count({ where: { userId } })).toBe(2);
    });

    it('refuses a scoped token on both routes', async () => {
      const { identity, accessToken, userId } = await accountWithTwoMethods();
      const scoped = await ctx.app.get(JwtService).signAsync({
        sub: userId,
        publicKey: identity.publicKeyCompressed,
        scope: 'device-approval',
      });
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;

      await listMethods(scoped).expect(403);
      const refused = await unlink(
        scoped,
        await signedUnlink(identity, accessToken, wallet)
      ).expect(403);
      expect(refused.body.message).toBe('Insufficient token scope');
      expect(await authMethods().count({ where: { userId } })).toBe(2);
    });

    it('refuses a token that carries no account key', async () => {
      const { identity, accessToken, userId } = await accountWithTwoMethods();
      const keyless = await ctx.app.get(JwtService).signAsync({ sub: userId });
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;

      const refused = await unlink(
        keyless,
        await signedUnlink(identity, accessToken, wallet)
      ).expect(403);
      expect(refused.body.message).toBe('Insufficient token scope');
      expect(await authMethods().count({ where: { userId } })).toBe(2);
    });

    it('answers 404 for a method belonging to another account, and deletes nothing', async () => {
      const mine = await accountWithTwoMethods();
      const theirs = await accountWithTwoMethods();
      const theirWallet = (
        await authMethods().findOneOrFail({ where: { userId: theirs.userId, kind: 'wallet' } })
      ).id;

      const res = await unlink(
        mine.accessToken,
        await signedUnlink(mine.identity, mine.accessToken, theirWallet)
      ).expect(404);
      expect(res.body.message).toBe('Unknown login method');
      expect(await authMethods().count({ where: { userId: theirs.userId } })).toBe(2);
      expect(await authMethods().count({ where: { userId: mine.userId } })).toBe(2);
    });

    it('leaves exactly one row when two unlinks race', async () => {
      const { identity, accessToken, userId } = await accountWithWalletsOnly(2);
      const methods = await authMethods().find({ where: { userId } });
      // Both bodies are signed up front: a challenge is single-use, so the race
      // has to be between two independently valid unlinks.
      const first = await signedUnlink(identity, accessToken, methods[0].id);
      const second = await signedUnlink(identity, accessToken, methods[1].id);

      const statuses = (
        await Promise.all([unlink(accessToken, first), unlink(accessToken, second)])
      ).map((res) => res.status);

      expect(statuses.sort()).toEqual([200, 409]);
      expect(await authMethods().count({ where: { userId } })).toBe(1);
    });

    it('takes the account auth-method lock before it counts', async () => {
      const { identity, accessToken, userId } = await accountWithTwoMethods();
      const wallet = (await authMethods().findOneOrFail({ where: { userId, kind: 'wallet' } })).id;

      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.startTransaction();
      try {
        await holder.query('SELECT pg_advisory_xact_lock($1::bigint)', [
          authMethodLockKey(userId).toString(),
        ]);

        let settled = false;
        const pending = unlink(accessToken, await signedUnlink(identity, accessToken, wallet)).then(
          (res) => {
            settled = true;
            return res;
          }
        );
        await waitForAdvisoryLockWait(db.dataSource);
        expect(settled).toBe(false);
        expect(await authMethods().count({ where: { userId } })).toBe(2);

        await holder.rollbackTransaction();
        expect((await pending).status).toBe(200);
        expect(await authMethods().count({ where: { userId } })).toBe(1);
      } finally {
        if (holder.isTransactionActive) {
          await holder.rollbackTransaction();
        }
        await holder.release();
      }
    });
  });
});
