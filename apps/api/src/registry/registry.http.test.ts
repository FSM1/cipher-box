import { INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OpsModule } from '../ops/ops.module';
import { FakeRepository } from '../testing/fake-repo';
import { fakeConfig } from '../testing/fakes';
import { AccountController } from './account.controller';
import { NameInventory } from './entities/name-inventory.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { PinStore } from './pin-store';
import { RegistryController } from './registry.controller';
import { RegistryService } from './services/registry.service';

const SECRET = 'registry-test-secret';
const GIB = 1024 * 1024 * 1024;

/** Records physical unpins so the refcount-zero decision is observable in HTTP tests. */
class FakePinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<void> {
    this.unpinned.push(cid);
  }
}

describe('registry HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let userRepo: FakeRepository<User>;
  let nameRepo: FakeRepository<NameInventory>;
  let pinRepo: FakeRepository<PinnedCid>;
  let pinStore: FakePinStore;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;

    userRepo = new FakeRepository<User>();
    nameRepo = new FakeRepository<NameInventory>();
    pinRepo = new FakeRepository<PinnedCid>();
    pinStore = new FakePinStore();
    jwt = new JwtService();

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        OpsModule,
        JwtModule.register({ secret: SECRET, signOptions: { expiresIn: 900 } }),
      ],
      controllers: [RegistryController, AccountController],
      providers: [
        RegistryService,
        JwtAuthGuard,
        { provide: PinStore, useValue: pinStore },
        {
          provide: ConfigService,
          useValue: fakeConfig({ QUOTA_DEFAULT_BYTES: String(10 * GIB) }).service,
        },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(NameInventory), useValue: nameRepo },
        { provide: getRepositoryToken(PinnedCid), useValue: pinRepo },
      ],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
    if (priorJwtSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = priorJwtSecret;
    }
  });

  /** Seed an account and mint a valid access token for it. */
  async function account(overrides: Partial<User> = {}): Promise<{ id: string; token: string }> {
    const priv = secp256k1.utils.randomPrivateKey();
    const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
    const user = await userRepo.save({ publicKey, byo: false, ...overrides } as never);
    const token = await jwt.signAsync({ sub: user.id, publicKey }, { secret: SECRET });
    return { id: user.id, token };
  }

  describe('register — register-first, idempotency', () => {
    it('registers a name with its head and content, reflected in the inventory', async () => {
      const acct = await account();
      const res = await request(http)
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'k51regA', headCid: 'bafyHeadA', contentCids: ['bafyC1', 'bafyC2'] }])
        .expect(201);
      expect(res.body).toEqual({ names: 1, cids: 3 });
      expect(nameRepo.rows.filter((r) => r.accountId === acct.id)).toHaveLength(1);
      expect(
        pinRepo.rows
          .filter((r) => r.accountId === acct.id)
          .map((r) => r.cid)
          .sort()
      ).toEqual(['bafyC1', 'bafyC2', 'bafyHeadA']);
    });

    it('is idempotent: replaying a batch adds no duplicate rows', async () => {
      const acct = await account();
      const batch = [{ ipnsName: 'k51idem', headCid: 'bafyIdem', contentCids: ['bafyDup'] }];
      await request(http)
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(batch)
        .expect(201);
      await request(http)
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(batch)
        .expect(201);
      expect(nameRepo.rows.filter((r) => r.ipnsName === 'k51idem')).toHaveLength(1);
      expect(
        pinRepo.rows.filter((r) => r.accountId === acct.id && r.cid === 'bafyDup')
      ).toHaveLength(1);
    });

    it('fail-closed: a malformed entry is refused wholesale, writing no rows', async () => {
      const acct = await account();
      const before = nameRepo.rows.length;
      // Invalid ipnsName (illegal chars) — the whole request 400s.
      await request(http)
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'not a name!', contentCids: ['bafyX'] }])
        .expect(400);
      // Unknown property on an entry — forbidNonWhitelisted rejects it.
      await request(http)
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'k51ok', contentCids: [], sneaky: 'no' }])
        .expect(400);
      expect(nameRepo.rows.length).toBe(before);
      expect(pinRepo.rows.some((r) => r.cid === 'bafyX')).toBe(false);
    });
  });

  describe('retire — union liveness, refcounted unpin', () => {
    it('keeps a shared CID pinned until the last account retires, then unpins', async () => {
      const alice = await account();
      const bob = await account();
      const shared = 'bafySharedHttp';
      for (const who of [alice, bob]) {
        await request(http)
          .post('/registry/register')
          .set('Authorization', `Bearer ${who.token}`)
          .send([{ ipnsName: `k51${who.id.slice(0, 8)}`, contentCids: [shared] }])
          .expect(201);
      }

      const first = await request(http)
        .post('/registry/retire')
        .set('Authorization', `Bearer ${alice.token}`)
        .send([shared])
        .expect(201);
      expect(first.body).toEqual({ retired: 1, unpinned: 0 });
      expect(pinStore.unpinned).not.toContain(shared);
      expect(pinRepo.rows.filter((r) => r.cid === shared)).toHaveLength(1);

      const second = await request(http)
        .post('/registry/retire')
        .set('Authorization', `Bearer ${bob.token}`)
        .send([shared])
        .expect(201);
      expect(second.body).toEqual({ retired: 1, unpinned: 1 });
      expect(pinStore.unpinned).toContain(shared);
      expect(pinRepo.rows.filter((r) => r.cid === shared)).toHaveLength(0);
    });
  });

  describe('quota — hosted authoritative vs BYO advisory', () => {
    it('sums the account pin rows and reports the env-default limit for a hosted account', async () => {
      const acct = await account();
      await pinRepo.save({
        accountId: acct.id,
        cid: 'bafyQ',
        size: '512',
        advisory: false,
      } as never);
      const res = await request(http)
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(res.body).toEqual({ usedBytes: 512, limitBytes: 10 * GIB, advisory: false });
    });

    it('flips advisory once the account enables BYO', async () => {
      const acct = await account();
      const before = await request(http)
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(before.body.advisory).toBe(false);

      const patched = await request(http)
        .patch('/account/byo')
        .set('Authorization', `Bearer ${acct.token}`)
        .send({ byo: true })
        .expect(200);
      expect(patched.body).toEqual({ byo: true });

      const after = await request(http)
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(after.body.advisory).toBe(true);
    });
  });

  describe('auth', () => {
    it('requires authentication on every route', async () => {
      await request(http).post('/registry/register').send([]).expect(401);
      await request(http).post('/registry/retire').send([]).expect(401);
      await request(http).get('/account/quota').expect(401);
      await request(http).patch('/account/byo').send({ byo: true }).expect(401);
    });
  });
});
