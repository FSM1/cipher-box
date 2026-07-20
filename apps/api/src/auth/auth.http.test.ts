import { INestApplication } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import request from 'supertest';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { FakeRepository } from '../testing/fake-repo';
import { fakeConfig } from '../testing/fakes';
import { ConfigService } from '@nestjs/config';
import { AuthController } from './auth.controller';
import { AuthMethod } from './entities/auth-method.entity';
import { RefreshToken } from './entities/refresh-token.entity';
import { User } from './entities/user.entity';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { AuthService } from './services/auth.service';
import { ChallengeService } from './services/challenge.service';
import { IdentityService } from './services/identity.service';
import { SiweService } from './services/siwe.service';
import { TestAuthService } from './services/test-auth.service';
import { TokenService } from './services/token.service';

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

describe('auth HTTP flows', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let userRepo: FakeRepository<User>;
  let methodRepo: FakeRepository<AuthMethod>;
  let tokenRepo: FakeRepository<RefreshToken>;
  let configValues: Record<string, string | undefined>;

  beforeAll(async () => {
    userRepo = new FakeRepository<User>();
    methodRepo = new FakeRepository<AuthMethod>();
    tokenRepo = new FakeRepository<RefreshToken>();
    const config = fakeConfig({ NODE_ENV: 'test', TEST_LOGIN_SECRET: 'e2e-secret' });
    configValues = config.values;

    const moduleRef = await Test.createTestingModule({
      imports: [JwtModule.register({ secret: 'test-secret', signOptions: { expiresIn: 900 } })],
      controllers: [AuthController],
      providers: [
        AuthService,
        TestAuthService,
        TokenService,
        ChallengeService,
        IdentityService,
        SiweService,
        JwtAuthGuard,
        { provide: Clock, useClass: SystemClock },
        { provide: Entropy, useClass: SystemEntropy },
        { provide: ConfigService, useValue: config.service },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(AuthMethod), useValue: methodRepo },
        { provide: getRepositoryToken(RefreshToken), useValue: tokenRepo },
      ],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  beforeEach(() => {
    configValues.NODE_ENV = 'test';
    configValues.TEST_LOGIN_SECRET = 'e2e-secret';
  });

  async function identityLogin(identity = newIdentity()) {
    const challengeRes = await request(http)
      .post('/auth/challenge')
      .send({ publicKey: identity.publicKeyCompressed })
      .expect(200);
    const loginRes = await request(http)
      .post('/auth/login')
      .send({
        publicKey: identity.publicKeyCompressed,
        challenge: challengeRes.body.challenge,
        signature: signChallenge(challengeRes.body.challenge, identity.privateKey),
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
      expect(
        userRepo.rows.filter((u) => u.publicKey === identity.publicKeyCompressed)
      ).toHaveLength(1);
    });

    it('keys the account by the canonical compressed publicKey regardless of encoding', async () => {
      const identity = newIdentity();
      const challengeRes = await request(http)
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyUncompressed })
        .expect(200);
      await request(http)
        .post('/auth/login')
        .send({
          publicKey: identity.publicKeyUncompressed,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(challengeRes.body.challenge, identity.privateKey),
        })
        .expect(200);
      expect(
        userRepo.rows.filter((u) => u.publicKey === identity.publicKeyCompressed)
      ).toHaveLength(1);
    });

    it('rejects a signature from the wrong key', async () => {
      const identity = newIdentity();
      const wrongKey = newIdentity();
      const challengeRes = await request(http)
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyCompressed })
        .expect(200);
      await request(http)
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
      const challengeRes = await request(http)
        .post('/auth/challenge')
        .send({ publicKey: identity.publicKeyCompressed })
        .expect(200);
      const body = {
        publicKey: identity.publicKeyCompressed,
        challenge: challengeRes.body.challenge,
        signature: signChallenge(challengeRes.body.challenge, identity.privateKey),
      };
      await request(http).post('/auth/login').send(body).expect(200);
      await request(http).post('/auth/login').send(body).expect(401);
    });

    it('rejects a challenge issued to a different publicKey', async () => {
      const victim = newIdentity();
      const attacker = newIdentity();
      const challengeRes = await request(http)
        .post('/auth/challenge')
        .send({ publicKey: victim.publicKeyCompressed })
        .expect(200);
      await request(http)
        .post('/auth/login')
        .send({
          publicKey: attacker.publicKeyCompressed,
          challenge: challengeRes.body.challenge,
          signature: signChallenge(challengeRes.body.challenge, attacker.privateKey),
        })
        .expect(401);
    });

    it('rejects malformed publicKeys and unexpected properties', async () => {
      await request(http).post('/auth/challenge').send({ publicKey: 'not-hex' }).expect(400);
      await request(http)
        .post('/auth/challenge')
        .send({ publicKey: newIdentity().publicKeyCompressed, privateKey: 'never-send-this' })
        .expect(400);
    });
  });

  describe('refresh rotation', () => {
    it('rotates via body, and reuse of the old token kills the family', async () => {
      const { loginRes } = await identityLogin();
      const firstRefreshToken = loginRes.body.refreshToken;

      const rotated = await request(http)
        .post('/auth/refresh')
        .send({ refreshToken: firstRefreshToken })
        .expect(200);
      expect(rotated.body.refreshToken).not.toBe(firstRefreshToken);

      // Reuse of the already-rotated token: 401 and the successor dies too.
      await request(http)
        .post('/auth/refresh')
        .send({ refreshToken: firstRefreshToken })
        .expect(401);
      await request(http)
        .post('/auth/refresh')
        .send({ refreshToken: rotated.body.refreshToken })
        .expect(401);
    });

    it('rotates via the HTTP-only cookie when the body is empty', async () => {
      const { loginRes } = await identityLogin();
      await request(http)
        .post('/auth/refresh')
        .set('Cookie', `refreshToken=${loginRes.body.refreshToken}`)
        .send({})
        .expect(200);
    });

    it('rejects a missing token', async () => {
      await request(http).post('/auth/refresh').send({}).expect(401);
    });
  });

  describe('logout', () => {
    it('revokes every refresh token for the account', async () => {
      const { loginRes } = await identityLogin();
      await request(http)
        .post('/auth/logout')
        .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
        .expect(200);
      await request(http)
        .post('/auth/refresh')
        .send({ refreshToken: loginRes.body.refreshToken })
        .expect(401);
    });

    it('requires a valid access token', async () => {
      await request(http).post('/auth/logout').expect(401);
      await request(http).post('/auth/logout').set('Authorization', 'Bearer bogus').expect(401);
    });
  });

  describe('SIWE secondary auth', () => {
    async function siweSign(account: ReturnType<typeof privateKeyToAccount>) {
      const nonceRes = await request(http).post('/auth/siwe/challenge').send({}).expect(200);
      const message = createSiweMessage({
        address: account.address,
        chainId: 1,
        domain: 'localhost:5173',
        nonce: nonceRes.body.nonce,
        uri: 'http://localhost:5173',
        version: '1',
      });
      const signature = await account.signMessage({ message });
      return { message, signature };
    }

    it('refuses login for an unlinked wallet — no implicit creation through SIWE', async () => {
      const account = privateKeyToAccount(generatePrivateKey());
      const { message, signature } = await siweSign(account);
      await request(http).post('/auth/siwe/login').send({ message, signature }).expect(401);
    });

    it('links a wallet to the authenticated account, then logs in with it', async () => {
      const { loginRes } = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());

      const link = await siweSign(account);
      await request(http)
        .post('/auth/siwe/link')
        .set('Authorization', `Bearer ${loginRes.body.accessToken}`)
        .send(link)
        .expect(201);

      const login = await siweSign(account);
      const siweLoginRes = await request(http).post('/auth/siwe/login').send(login).expect(200);
      expect(jwtPayload(siweLoginRes.body.accessToken).sub).toBe(
        jwtPayload(loginRes.body.accessToken).sub
      );
    });

    it('refuses to link a wallet already linked to another account', async () => {
      const first = await identityLogin();
      const second = await identityLogin();
      const account = privateKeyToAccount(generatePrivateKey());

      const link = await siweSign(account);
      await request(http)
        .post('/auth/siwe/link')
        .set('Authorization', `Bearer ${first.loginRes.body.accessToken}`)
        .send(link)
        .expect(201);

      const conflicting = await siweSign(account);
      await request(http)
        .post('/auth/siwe/link')
        .set('Authorization', `Bearer ${second.loginRes.body.accessToken}`)
        .send(conflicting)
        .expect(409);
    });

    it('rejects a tampered SIWE signature', async () => {
      const account = privateKeyToAccount(generatePrivateKey());
      const other = privateKeyToAccount(generatePrivateKey());
      const nonceRes = await request(http).post('/auth/siwe/challenge').send({}).expect(200);
      const message = createSiweMessage({
        address: account.address,
        chainId: 1,
        domain: 'localhost:5173',
        nonce: nonceRes.body.nonce,
        uri: 'http://localhost:5173',
        version: '1',
      });
      const signature = await other.signMessage({ message });
      await request(http).post('/auth/siwe/login').send({ message, signature }).expect(401);
    });
  });

  describe('staging-gated test-login', () => {
    it('is hard-blocked in production regardless of the secret', async () => {
      configValues.NODE_ENV = 'production';
      await request(http)
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(403);
    });

    it('is disabled when TEST_LOGIN_SECRET is unset', async () => {
      configValues.TEST_LOGIN_SECRET = undefined;
      await request(http)
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'anything' })
        .expect(403);
    });

    it('rejects a wrong secret', async () => {
      await request(http)
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'wrong' })
        .expect(401);
    });

    it('logs in deterministically with the right secret', async () => {
      const first = await request(http)
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(200);
      expect(first.body.isNewUser).toBe(true);
      expect(first.body.publicKey).toMatch(/^(02|03)[0-9a-f]{64}$/);
      expect(first.body.privateKey).toMatch(/^[0-9a-f]{64}$/);

      const second = await request(http)
        .post('/auth/test-login')
        .send({ handle: 'e2e@test.local', secret: 'e2e-secret' })
        .expect(200);
      expect(second.body.isNewUser).toBe(false);
      expect(second.body.publicKey).toBe(first.body.publicKey);
    });

    it('yields an identity that can also log in via challenge-signature', async () => {
      const testRes = await request(http)
        .post('/auth/test-login')
        .send({ handle: 'crossover@test.local', secret: 'e2e-secret' })
        .expect(200);

      const challengeRes = await request(http)
        .post('/auth/challenge')
        .send({ publicKey: testRes.body.publicKey })
        .expect(200);
      const loginRes = await request(http)
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
});
