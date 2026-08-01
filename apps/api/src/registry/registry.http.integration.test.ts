import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { fakeConfig } from '../testing/fakes';
import {
  createHttpIntegrationApp,
  HttpIntegrationApp,
  seedAccount,
} from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { AccountController } from './account.controller';
import { MAX_CONTENT_CIDS } from './dto/registry.dto';
import { NameInventory } from './entities/name-inventory.entity';
import { PinnedCid } from './entities/pinned-cid.entity';
import { PinStore } from './pin-store';
import { REGISTRY_BATCH_REFUSED } from './registry-error-codes';
import { RegistryController } from './registry.controller';
import { AccountService } from './services/account.service';
import { RegistryService } from './services/registry.service';

/**
 * The registry + account HTTP surface re-homed onto a REAL Postgres (#725): the
 * register/retire/quota/BYO/delete contract end-to-end through the booted app,
 * the fail-closed validation pipes, and the auth guard — asserting the real
 * `pinned_cids`/`name_inventory`/`users` rows a fake DataSource could only
 * pretend to write. The deep advisory-lock/refcount concurrency proofs live in
 * the service integration suites; here the HTTP boundary and its DB effects are
 * verified together.
 */

const GIB = 1024 * 1024 * 1024;

/** Records physical unpins so the refcount-zero decision is observable. */
class FakePinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

describe('registry HTTP surface (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let jwt: JwtService;
  let pinStore: FakePinStore;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    pinStore = new FakePinStore();
    ctx = await createHttpIntegrationApp({
      db,
      entities: [User, NameInventory, PinnedCid],
      controllers: [RegistryController, AccountController],
      providers: [
        RegistryService,
        AccountService,
        JwtAuthGuard,
        { provide: PinStore, useValue: pinStore },
        {
          provide: ConfigService,
          useValue: fakeConfig({
            QUOTA_DEFAULT_BYTES: String(10 * GIB),
            DB_ADVISORY_LOCK_TIMEOUT_MS: '0',
          }).service,
        },
      ],
    });
    jwt = ctx.app.get(JwtService);
  });

  afterAll(async () => {
    await ctx?.close();
    await db?.teardown();
  });

  afterEach(async () => {
    pinStore.unpinned.length = 0;
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  const http = () => ctx.http;

  /** Seed an account row and mint a valid access token for it. */
  async function account(overrides: Partial<User> = {}): Promise<{ id: string; token: string }> {
    const { userId, token } = await seedAccount(db, jwt, overrides);
    return { id: userId, token };
  }

  async function pinsFor(accountId: string): Promise<PinnedCid[]> {
    return db.dataSource.getRepository(PinnedCid).find({ where: { accountId } });
  }

  async function namesFor(accountId: string): Promise<NameInventory[]> {
    return db.dataSource.getRepository(NameInventory).find({ where: { accountId } });
  }

  describe('register — register-first, idempotency', () => {
    it('registers a name with its head and content, reflected in the inventory', async () => {
      const acct = await account();
      const res = await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'k51regA', headCid: 'bafyHeadA', contentCids: ['bafyC1', 'bafyC2'] }])
        .expect(201);
      expect(res.body).toEqual({ names: 1, cids: 3 });
      expect(await namesFor(acct.id)).toHaveLength(1);
      expect((await pinsFor(acct.id)).map((r) => r.cid).sort()).toEqual([
        'bafyC1',
        'bafyC2',
        'bafyHeadA',
      ]);
    });

    it('is idempotent: replaying a batch adds no duplicate rows', async () => {
      const acct = await account();
      const batch = [{ ipnsName: 'k51idem', headCid: 'bafyIdem', contentCids: ['bafyDup'] }];
      await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(batch)
        .expect(201);
      await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(batch)
        .expect(201);
      expect((await namesFor(acct.id)).filter((r) => r.ipnsName === 'k51idem')).toHaveLength(1);
      expect((await pinsFor(acct.id)).filter((r) => r.cid === 'bafyDup')).toHaveLength(1);
    });

    it('fail-closed: a malformed entry is refused wholesale, writing no rows', async () => {
      const acct = await account();
      // Invalid ipnsName (illegal chars) — the whole request 400s.
      await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'not a name!', contentCids: ['bafyX'] }])
        .expect(400);
      // Unknown property on an entry — forbidNonWhitelisted rejects it.
      await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'k51ok', contentCids: [], sneaky: 'no' }])
        .expect(400);
      expect(await namesFor(acct.id)).toHaveLength(0);
      expect((await pinsFor(acct.id)).some((r) => r.cid === 'bafyX')).toBe(false);
    });

    it('refuses an over-cap contentCids and stamps the batch-refused code', async () => {
      const acct = await account();
      const contentCids = Array.from({ length: MAX_CONTENT_CIDS + 1 }, (_, i) => `bafyOverCap${i}`);
      const response = await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([{ ipnsName: 'k51overcap', contentCids }])
        .expect(400);
      // The engine's failure valve dead-letters on this code, never on the
      // status alone — a 400 from anything but this gate must not carry it.
      expect(response.body.code).toBe(REGISTRY_BATCH_REFUSED);
      expect(await namesFor(acct.id)).toHaveLength(0);
    });

    it('splits an over-cap version across entries under one name, keeping the head', async () => {
      const acct = await account();
      // The shape the engine's chunker sends: the head rides the first entry,
      // the remainder follows as content-only entries under the same name.
      await request(http())
        .post('/registry/register')
        .set('Authorization', `Bearer ${acct.token}`)
        .send([
          { ipnsName: 'k51chunked', headCid: 'bafyChunkedHead', contentCids: ['bafyChunkA'] },
          { ipnsName: 'k51chunked', contentCids: ['bafyChunkB'] },
        ])
        .expect(201);
      const names = await namesFor(acct.id);
      expect(names).toHaveLength(1);
      expect(names[0].headCid).toBe('bafyChunkedHead');
      const cids = (await pinsFor(acct.id)).map((r) => r.cid).sort();
      expect(cids).toEqual(['bafyChunkA', 'bafyChunkB', 'bafyChunkedHead']);
    });
  });

  describe('retire — union liveness, refcounted unpin', () => {
    it('keeps a shared CID pinned until the last account retires, then unpins', async () => {
      const alice = await account();
      const bob = await account();
      const shared = 'bafySharedHttp';
      for (const who of [alice, bob]) {
        await request(http())
          .post('/registry/register')
          .set('Authorization', `Bearer ${who.token}`)
          .send([{ ipnsName: `k51${who.id.slice(0, 8)}`, contentCids: [shared] }])
          .expect(201);
      }

      const first = await request(http())
        .post('/registry/retire')
        .set('Authorization', `Bearer ${alice.token}`)
        .send([shared])
        .expect(201);
      expect(first.body).toEqual({ retired: 1, unpinned: 0 });
      expect(pinStore.unpinned).not.toContain(shared);
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { cid: shared } })
      ).toHaveLength(1);

      const second = await request(http())
        .post('/registry/retire')
        .set('Authorization', `Bearer ${bob.token}`)
        .send([shared])
        .expect(201);
      expect(second.body).toEqual({ retired: 1, unpinned: 1 });
      expect(pinStore.unpinned).toContain(shared);
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { cid: shared } })
      ).toHaveLength(0);
    });

    it('rejects an over-length target at the pipe (256-char cap)', async () => {
      const acct = await account();
      await request(http())
        .post('/registry/retire')
        .set('Authorization', `Bearer ${acct.token}`)
        .send(['a'.repeat(257)])
        .expect(400);
    });
  });

  describe('quota — hosted authoritative vs BYO advisory', () => {
    it('sums the account pin rows and reports the env-default limit for a hosted account', async () => {
      const acct = await account();
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: acct.id, cid: 'bafyQ', size: '512', advisory: false });
      const res = await request(http())
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(res.body).toEqual({
        usedBytes: 512,
        pinnedBytes: 512,
        limitBytes: 10 * GIB,
        advisory: false,
      });
    });

    it('reports usedBytes as the GATED sum when advisory rows are present, pinnedBytes as all rows', async () => {
      const acct = await account();
      const pins = db.dataSource.getRepository(PinnedCid);
      await pins.save({ accountId: acct.id, cid: 'bafyHostedQ', size: '512', advisory: false });
      await pins.save({ accountId: acct.id, cid: 'bafyAdvisoryQ', size: '9000', advisory: true });

      const res = await request(http())
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);

      // 512 is what the upload gate would enforce; the advisory 9000 is not.
      expect(res.body.usedBytes).toBe(512);
      expect(res.body.pinnedBytes).toBe(9512);
    });

    it('flips advisory once the account enables BYO', async () => {
      const acct = await account();
      const before = await request(http())
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(before.body.advisory).toBe(false);

      const patched = await request(http())
        .patch('/account/byo')
        .set('Authorization', `Bearer ${acct.token}`)
        .send({ byo: true })
        .expect(200);
      expect(patched.body).toEqual({ byo: true });

      const after = await request(http())
        .get('/account/quota')
        .set('Authorization', `Bearer ${acct.token}`)
        .expect(200);
      expect(after.body.advisory).toBe(true);
    });
  });

  describe('delete — account hard-delete cascade', () => {
    it('hard-deletes the caller rows, purges its mailbox, unpins sole CIDs, and reports counts', async () => {
      const acct = await account();
      await db.dataSource
        .getRepository(NameInventory)
        .save({ accountId: acct.id, ipnsName: 'k51del', headCid: null });
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: acct.id, cid: 'bafyDelSole', size: '4', advisory: false });
      const user = await db.dataSource
        .getRepository(User)
        .findOneOrFail({ where: { id: acct.id } });
      await db.dataSource.query(
        `INSERT INTO mailbox_messages (recipient_public_key, idempotency_scope, blob, received_at)
         VALUES ($1, $2, $3, $4)`,
        [user.publicKey, 'scope', Buffer.from('x'), new Date()]
      );

      const res = await request(http())
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
      expect(
        await db.dataSource.getRepository(User).findOne({ where: { id: acct.id } })
      ).toBeNull();
      expect(await namesFor(acct.id)).toHaveLength(0);
      expect(await pinsFor(acct.id)).toHaveLength(0);
      const mailbox: unknown[] = await db.dataSource.query(
        'SELECT 1 FROM mailbox_messages WHERE recipient_public_key = $1',
        [user.publicKey]
      );
      expect(mailbox).toHaveLength(0);
    });

    it('leaves a co-registered CID pinned and the other account intact', async () => {
      const alice = await account();
      const bob = await account();
      const shared = 'bafySharedDel';
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: alice.id, cid: shared, size: '4', advisory: false });
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: bob.id, cid: shared, size: '4', advisory: false });

      const res = await request(http())
        .delete('/account')
        .set('Authorization', `Bearer ${alice.token}`)
        .expect(200);

      expect(res.body.unpinned).toBe(0);
      expect(pinStore.unpinned).not.toContain(shared);
      expect(
        (await db.dataSource.getRepository(PinnedCid).find({ where: { cid: shared } })).map(
          (r) => r.accountId
        )
      ).toEqual([bob.id]);
      expect(
        await db.dataSource.getRepository(User).findOne({ where: { id: bob.id } })
      ).not.toBeNull();
    });
  });

  describe('auth', () => {
    it('requires authentication on every route', async () => {
      await request(http()).post('/registry/register').send([]).expect(401);
      await request(http()).post('/registry/retire').send([]).expect(401);
      await request(http()).get('/account/quota').expect(401);
      await request(http()).patch('/account/byo').send({ byo: true }).expect(401);
      await request(http()).delete('/account').expect(401);
    });
  });
});
