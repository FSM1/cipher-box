import { INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getRepositoryToken } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import request from 'supertest';
import { DataSource, FindOperator } from 'typeorm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { MailboxMessage } from '../mailbox/entities/mailbox-message.entity';
import { OpsModule } from '../ops/ops.module';
import { FakeRepository } from '../testing/fake-repo';
import { fakeConfig } from '../testing/fakes';
import { AccountController } from './account.controller';
import { NameInventory } from './entities/name-inventory.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { PinStore } from './pin-store';
import { RegistryController } from './registry.controller';
import { AccountService } from './services/account.service';
import { RegistryService } from './services/registry.service';

const SECRET = 'registry-test-secret';
const GIB = 1024 * 1024 * 1024;

/** Records physical unpins so the refcount-zero decision is observable in HTTP tests. */
class FakePinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

/** Matches plain equality plus the `In([...])` operator the bulk paths use. */
function inMatch(row: Record<string, unknown>, where: Record<string, unknown>): boolean {
  return Object.entries(where).every(([key, expected]) => {
    if (expected instanceof FindOperator) {
      if (expected.type === 'in') {
        return (expected.value as unknown[]).includes(row[key]);
      }
      throw new Error(`InAwareRepository: unsupported operator ${expected.type}`);
    }
    return row[key] === expected;
  });
}

/** FakeRepository plus the `In`/array-save/`sum` surface the bulk paths need. */
class InAwareRepository<T extends { id: string }> extends FakeRepository<T> {
  override async find(options: { where?: Record<string, unknown> } = {}): Promise<T[]> {
    const where = options.where;
    if (!where) {
      return [...this.rows];
    }
    return this.rows.filter((row) => inMatch(row as Record<string, unknown>, where));
  }

  override async delete(criteria: Record<string, unknown>): Promise<{ affected: number }> {
    const before = this.rows.length;
    this.rows = this.rows.filter((row) => !inMatch(row as Record<string, unknown>, criteria));
    return { affected: before - this.rows.length };
  }

  override save(entity: Partial<T>): Promise<T>;
  override save(entities: Partial<T>[]): Promise<T[]>;
  override async save(entities: Partial<T> | Partial<T>[]): Promise<T | T[]> {
    if (Array.isArray(entities)) {
      const saved: T[] = [];
      for (const entity of entities) {
        saved.push(await super.save(entity));
      }
      return saved;
    }
    return super.save(entities);
  }

  /** Emulates the `COALESCE(SUM(size), 0)` aggregate `sumPinnedBytes` runs, keyed by accountId. */
  createQueryBuilder(_alias?: string): SumQueryBuilder {
    const allRows = this.rows;
    let accountId: string | undefined;
    const qb: SumQueryBuilder = {
      select: () => qb,
      where: (_clause, params) => {
        accountId = params?.accountId as string | undefined;
        return qb;
      },
      getRawOne: async () => {
        const used = allRows
          .filter((row) => (row as { accountId?: string }).accountId === accountId)
          .reduce((total, row) => total + BigInt((row as { size?: string }).size ?? '0'), 0n);
        return { used: used.toString() };
      },
    };
    return qb;
  }
}

interface SumQueryBuilder {
  select: (selection: string, alias: string) => SumQueryBuilder;
  where: (clause: string, params?: Record<string, unknown>) => SumQueryBuilder;
  getRawOne: () => Promise<{ used: string }>;
}

/** A DataSource whose transaction runs inline against the in-memory repos. */
function fakeDataSource(repos: Array<[unknown, unknown]>): DataSource {
  const byEntity = new Map(repos);
  return {
    transaction: (runInTransaction: (manager: unknown) => unknown) =>
      runInTransaction({
        getRepository: (entity: unknown) => byEntity.get(entity),
        query: async () => [],
      }),
    createQueryRunner: () => ({
      connect: async () => undefined,
      query: async () => [],
      release: async () => undefined,
    }),
  } as unknown as DataSource;
}

describe('registry HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let userRepo: FakeRepository<User>;
  let nameRepo: InAwareRepository<NameInventory>;
  let pinRepo: InAwareRepository<PinnedCid>;
  let mailboxRepo: InAwareRepository<MailboxMessage>;
  let pinStore: FakePinStore;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;

    userRepo = new FakeRepository<User>();
    nameRepo = new InAwareRepository<NameInventory>();
    pinRepo = new InAwareRepository<PinnedCid>();
    mailboxRepo = new InAwareRepository<MailboxMessage>();
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
        AccountService,
        JwtAuthGuard,
        { provide: PinStore, useValue: pinStore },
        {
          provide: ConfigService,
          useValue: fakeConfig({ QUOTA_DEFAULT_BYTES: String(10 * GIB) }).service,
        },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(NameInventory), useValue: nameRepo },
        { provide: getRepositoryToken(PinnedCid), useValue: pinRepo },
        {
          provide: DataSource,
          useValue: fakeDataSource([
            [User, userRepo],
            [NameInventory, nameRepo],
            [PinnedCid, pinRepo],
            [MailboxMessage, mailboxRepo],
          ]),
        },
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
    try {
      const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
      const user = await userRepo.save({ publicKey, byo: false, ...overrides } as never);
      const token = await jwt.signAsync({ sub: user.id, publicKey }, { secret: SECRET });
      return { id: user.id, token };
    } finally {
      priv.fill(0);
    }
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

    it('rejects an over-length target at the pipe (256-char cap)', async () => {
      const acct = await account();
      await request(http)
        .post('/registry/retire')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(['a'.repeat(257)])
        .expect(400);
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

  describe('delete — account hard-delete cascade', () => {
    it('hard-deletes the caller rows, purges its mailbox, unpins sole CIDs, and reports counts', async () => {
      const acct = await account();
      await nameRepo.save({ accountId: acct.id, ipnsName: 'k51del', headCid: null } as never);
      await pinRepo.save({
        accountId: acct.id,
        cid: 'bafyDelSole',
        size: '4',
        advisory: false,
      } as never);
      const user = userRepo.rows.find((r) => r.id === acct.id)!;
      await mailboxRepo.save({
        recipientPublicKey: user.publicKey,
        idempotencyScope: 'scope',
        blob: Buffer.from('x'),
        receivedAt: new Date(),
      } as never);

      const res = await request(http)
        .delete('/account')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);

      expect(res.body).toEqual({
        namesRetired: 1,
        pinsRetired: 1,
        mailboxPurged: 1,
        unpinned: 1,
      });
      expect(pinStore.unpinned).toContain('bafyDelSole');
      expect(userRepo.rows.some((r) => r.id === acct.id)).toBe(false);
      expect(nameRepo.rows.some((r) => r.accountId === acct.id)).toBe(false);
      expect(pinRepo.rows.some((r) => r.accountId === acct.id)).toBe(false);
      expect(mailboxRepo.rows.some((r) => r.recipientPublicKey === user.publicKey)).toBe(false);
    });

    it('leaves a co-registered CID pinned and the other account intact', async () => {
      const alice = await account();
      const bob = await account();
      const shared = 'bafySharedDel';
      await pinRepo.save({ accountId: alice.id, cid: shared, size: '4', advisory: false } as never);
      await pinRepo.save({ accountId: bob.id, cid: shared, size: '4', advisory: false } as never);

      const res = await request(http)
        .delete('/account')
        .set('Authorization', `Bearer ${alice.token}`)
        .expect(200);

      expect(res.body.unpinned).toBe(0);
      expect(pinStore.unpinned).not.toContain(shared);
      expect(pinRepo.rows.filter((r) => r.cid === shared).map((r) => r.accountId)).toEqual([
        bob.id,
      ]);
      expect(userRepo.rows.some((r) => r.id === bob.id)).toBe(true);
    });
  });

  describe('auth', () => {
    it('requires authentication on every route', async () => {
      await request(http).post('/registry/register').send([]).expect(401);
      await request(http).post('/registry/retire').send([]).expect(401);
      await request(http).get('/account/quota').expect(401);
      await request(http).patch('/account/byo').send({ byo: true }).expect(401);
      await request(http).delete('/account').expect(401);
    });
  });
});
