import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { DataSource, EntityManager, FindOneOptions, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuthMethod } from '../../auth/entities/auth-method.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import { advisoryLockKey, pinDurabilityLockKey } from '../../common/advisory-lock';
import { MailboxMessage } from '../../mailbox/entities/mailbox-message.entity';
import { MailboxService } from '../../mailbox/services/mailbox.service';
import { RecordCache } from '../../republisher/entities/record-cache.entity';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { RegistryService } from './registry.service';
import { AccountService, DELETE_CHUNK_SIZE } from './account.service';

/**
 * The account hard-delete cascade proven on a REAL Postgres: the refcount unpin
 * across the delete/register phantom, the post-commit durability recount against
 * a concurrent upload, the bounded multi-chunk drain, a straggler pin racing the
 * residue step, the mailbox-post resurrection window, the auth-row cascade,
 * co-registered survival, and the lock-timeout 503. Real row/advisory locks and
 * FK cascades are genuine Postgres behavior no in-memory fake can exercise. Each
 * interleaving test pins the lock/re-check effect with a negative control that
 * reproduces the failure once the guard is stripped.
 */

function compressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

function token(): string {
  return randomBytes(16).toString('hex');
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Block until a backend is parked on an ungranted advisory lock — an observable
 * signal that the delete has actually reached and is WAITING on the contended
 * lock, replacing a fixed delay that only assumes it "should be blocked by now".
 * The suite runs serially and truncates between cases, so the only ungranted
 * advisory lock is the delete waiting on the gate holder's lock.
 */
async function waitForAdvisoryLockWait(ds: DataSource, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const waiting = await ds.query(
      `SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND NOT granted LIMIT 1`
    );
    if (waiting.length > 0) {
      return;
    }
    if (Date.now() > deadline) {
      throw new Error('timed out waiting for the delete to park on the advisory lock');
    }
    await delay(20);
  }
}

class RecordingPinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

interface Gate {
  reached: Promise<void>;
  release: () => void;
  onReach: () => Promise<void>;
}

function makeGate(): Gate {
  let signalReached!: () => void;
  let release!: () => void;
  const reached = new Promise<void>((resolve) => (signalReached = resolve));
  const open = new Promise<void>((resolve) => (release = resolve));
  return {
    reached,
    release,
    onReach: async () => {
      signalReached();
      await open;
    },
  };
}

interface GateHooks {
  /** No-op the advisory lock + lock_timeout, and drop the users-row lock — the
   * unserialized pre-fix path. */
  stripLock?: boolean;
  /** Pause the register path after it inserts its pin row (still holding the lock). */
  afterPinInsert?: () => Promise<void>;
  /** No-op the post-commit session advisory lock so the cascade's unpin does not
   * serialize on `pinDurabilityLockKey` — the pre-fix post-commit path. */
  stripDurabilityLock?: boolean;
}

/**
 * A DataSource that runs the real transaction but can strip the advisory locks
 * and pause the register path after its pin save, so a concurrent delete can be
 * observed to block (lock present) or to race (lock stripped).
 */
function gatedDataSource(real: DataSource, hooks: GateHooks): DataSource {
  const wrapUserRepo = (repo: Repository<User>): Repository<User> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'findOne') {
          return (options: FindOneOptions<User>) =>
            target.findOne(hooks.stripLock ? { ...options, lock: undefined } : options);
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

  const wrapPinRepo = (repo: Repository<PinnedCid>): Repository<PinnedCid> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'insert') {
          return async (entities: never) => {
            const result = await target.insert(entities);
            if (hooks.afterPinInsert) await hooks.afterPinInsert();
            return result;
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

  return {
    transaction: (runInTransaction: (manager: EntityManager) => Promise<unknown>) =>
      real.transaction((manager) => {
        const proxied = new Proxy(manager, {
          get(target, prop, receiver) {
            if (prop === 'query') {
              return async (sql: string, params?: unknown[]) => {
                if (hooks.stripLock && /pg_advisory_xact_lock|lock_timeout/i.test(sql)) {
                  return [];
                }
                return target.query(sql, params);
              };
            }
            if (prop === 'getRepository') {
              return (entity: unknown) => {
                const repo = target.getRepository(entity as never);
                if (entity === User) return wrapUserRepo(repo as Repository<User>);
                if (entity === PinnedCid) return wrapPinRepo(repo as Repository<PinnedCid>);
                return repo;
              };
            }
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function' ? value.bind(target) : value;
          },
        });
        return runInTransaction(proxied);
      }),
    createQueryRunner: () => {
      const runner = real.createQueryRunner();
      if (!hooks.stripDurabilityLock) {
        return runner;
      }
      return new Proxy(runner, {
        get(target, prop, receiver) {
          if (prop === 'query') {
            return async (sql: string, params?: unknown[]) => {
              if (/pg_advisory_lock\(|pg_advisory_unlock\(/i.test(sql)) {
                return [];
              }
              return target.query(sql, params);
            };
          }
          const value = Reflect.get(target, prop, receiver);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    },
  } as unknown as DataSource;
}

describe('AccountService cascade (real Postgres)', () => {
  let db: IntegrationDatabase;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users, mailbox_messages, record_cache CASCADE');
  });

  function deleteService(ds: DataSource, pinStore: PinStore, lockMs = '0'): AccountService {
    return new AccountService(
      db.dataSource.getRepository(User) as never,
      db.dataSource.getRepository(PinnedCid) as never,
      ds as never,
      pinStore,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: lockMs }).service
    );
  }

  function registerService(ds: DataSource, pinStore: PinStore): RegistryService {
    return new RegistryService(
      db.dataSource.getRepository(PinnedCid) as never,
      db.dataSource.getRepository(User) as never,
      ds as never,
      pinStore,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
    );
  }

  function mailboxService(userRepo: Repository<User>): MailboxService {
    return new MailboxService(
      db.dataSource.getRepository(MailboxMessage) as never,
      userRepo as never,
      db.dataSource as never,
      new IdentityService(),
      new FakeClock(),
      fakeConfig({ MAILBOX_PENDING_CAP: '100', DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
    );
  }

  async function seedAccount(): Promise<{ id: string; publicKey: string }> {
    const publicKey = compressedPublicKey();
    const user = await db.dataSource.getRepository(User).save({ publicKey, byo: false });
    return { id: user.id, publicKey };
  }

  async function seedPin(accountId: string, cid: string): Promise<void> {
    await db.dataSource
      .getRepository(PinnedCid)
      .save({ accountId, cid, size: '0', advisory: false });
  }

  describe('refcounted unpin', () => {
    it('unpins a sole-held CID and retires every row for the account', async () => {
      const { id, publicKey } = await seedAccount();
      const cid = token();
      await seedPin(id, cid);
      await db.dataSource.getRepository(NameInventory).save({ accountId: id, ipnsName: token() });
      await db.dataSource.getRepository(MailboxMessage).save({
        recipientPublicKey: publicKey,
        idempotencyScope: token(),
        blob: Buffer.from('x'),
        receivedAt: new Date(),
      });

      const pinStore = new RecordingPinStore();
      const result = await deleteService(db.dataSource, pinStore).deleteAccount(id);

      expect(result).toEqual({ namesRetired: 1, pinsRetired: 1, mailboxPurged: 1, unpinned: 1 });
      expect(pinStore.unpinned).toEqual([cid]);
      expect(await db.dataSource.getRepository(User).findOne({ where: { id } })).toBeNull();
    });

    it('does NOT unpin a CID co-registered by another account (union liveness)', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const cid = token();
      await seedPin(a.id, cid);
      await seedPin(b.id, cid);

      const pinStore = new RecordingPinStore();
      const result = await deleteService(db.dataSource, pinStore).deleteAccount(a.id);

      expect(result.unpinned).toBe(0);
      expect(pinStore.unpinned).toEqual([]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b.id]);
    });

    it('a register committing under the per-CID lock keeps the CID pinned; delete finds the survivor and does not unpin', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const cid = token();
      await seedPin(a.id, cid);

      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      const registerB = registerService(
        gatedDataSource(db.dataSource, { afterPinInsert: gate.onReach }),
        pinStore
      ).register(b.id, [{ ipnsName: token(), contentCids: [cid] }]);

      // register(B) has inserted (B, cid) and paused, still holding advisory(cid).
      await gate.reached;

      let deleteDone = false;
      const deleted = deleteService(db.dataSource, pinStore)
        .deleteAccount(a.id)
        .then((r) => {
          deleteDone = true;
          return r;
        });

      // delete(A) is blocked on register(B)'s advisory(cid) — it cannot reach its
      // survivor check, let alone unpin. Observe the actual lock wait, not a delay.
      await waitForAdvisoryLockWait(db.dataSource);
      expect(deleteDone).toBe(false);
      expect(pinStore.unpinned).toEqual([]);

      gate.release();
      await registerB;
      const result = await deleted;

      expect(result.unpinned).toBe(0);
      expect(pinStore.unpinned).toEqual([]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b.id]);
    });

    it('negative control — without the advisory lock, delete prematurely unpins a CID a concurrent register is adding', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const cid = token();
      await seedPin(a.id, cid);

      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      const registerB = registerService(
        gatedDataSource(db.dataSource, { stripLock: true, afterPinInsert: gate.onReach }),
        pinStore
      ).register(b.id, [{ ipnsName: token(), contentCids: [cid] }]);

      await gate.reached; // (B, cid) inserted but uncommitted

      // With no lock, delete runs concurrently: it deletes A's row and its
      // survivor check cannot see B's uncommitted insert, so it unpins the CID.
      const result = await deleteService(
        gatedDataSource(db.dataSource, { stripLock: true }),
        pinStore
      ).deleteAccount(a.id);

      gate.release();
      await registerB;

      expect(result.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b.id]);
    });

    it('drains a pin that races in after an empty pre-read rather than cascading it away un-unpinned', async () => {
      const a = await seedAccount();
      const cid = token();

      // The UNLOCKED pre-read observes no pins, then a pin commits into the gap
      // before the residue step. The in-lock straggler re-check must see it and
      // defer to another draining pass — never let the user delete cascade it
      // away un-unpinned (its FK is onDelete: CASCADE).
      let injected = false;
      const pinRepo = db.dataSource.getRepository(PinnedCid);
      const gatedPinRepo = new Proxy(pinRepo, {
        get(target, prop, receiver) {
          if (prop === 'find') {
            return async (options?: unknown) => {
              const rows = await target.find(options as never);
              if (!injected && (rows as unknown[]).length === 0) {
                injected = true;
                await seedPin(a.id, cid); // races in after the empty pre-read
              }
              return rows;
            };
          }
          const value = Reflect.get(target, prop, receiver);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }) as Repository<PinnedCid>;

      const pinStore = new RecordingPinStore();
      const service = new AccountService(
        db.dataSource.getRepository(User) as never,
        gatedPinRepo as never,
        db.dataSource as never,
        pinStore,
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
      );

      const result = await service.deleteAccount(a.id);

      // The straggler is drained and unpinned under its own per-CID lock, and the
      // account is fully removed — no residue, no leaked pin.
      expect(result.pinsRetired).toBe(1);
      expect(result.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { accountId: a.id } })
      ).toEqual([]);
      expect(await db.dataSource.getRepository(User).findOne({ where: { id: a.id } })).toBeNull();
    });

    it('drains a multi-chunk account to completion without wedging on lock_timeout', async () => {
      const { id } = await seedAccount();
      const cids = Array.from({ length: DELETE_CHUNK_SIZE + 5 }, () => token());
      await db.dataSource
        .getRepository(PinnedCid)
        .save(cids.map((cid) => ({ accountId: id, cid, size: '1', advisory: false })));
      await db.dataSource.getRepository(NameInventory).save({ accountId: id, ipnsName: token() });

      // A real (bounded) lock timeout: the pre-fix single unbounded batch of this
      // many advisory keys is exactly what would blow past it and wedge.
      const pinStore = new RecordingPinStore();
      const result = await deleteService(db.dataSource, pinStore, '2000').deleteAccount(id);

      expect(result.pinsRetired).toBe(cids.length);
      expect(result.namesRetired).toBe(1);
      expect(result.unpinned).toBe(cids.length);
      expect(new Set(pinStore.unpinned)).toEqual(new Set(cids));
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { accountId: id } })
      ).toEqual([]);
      expect(await db.dataSource.getRepository(User).findOne({ where: { id } })).toBeNull();
    });

    it('a concurrent upload committing a live pin into the post-commit gap keeps the CID pinned; the cascade recounts under the durability lock and skips the unpin', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const cid = token();
      await seedPin(a.id, cid);

      const pinStore = new RecordingPinStore();

      // Model the concurrent upload's commit → pin span by HOLDING the same
      // per-CID durability session lock the upload path holds. The delete's
      // transaction commits (A gone, unpinCids=[cid]) but its post-commit unpin
      // blocks on this lock; while blocked the upload's live (B, cid) row commits.
      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.query('SELECT pg_advisory_lock($1::bigint)', [
        pinDurabilityLockKey(cid).toString(),
      ]);

      const deleted = deleteService(db.dataSource, pinStore).deleteAccount(a.id);

      // The chunk has committed (A gone) and the post-commit unpin now parks on
      // the durability lock the holder owns — wait for that actual lock wait.
      await waitForAdvisoryLockWait(db.dataSource);
      await seedPin(b.id, cid); // the upload's live pin row commits into the gap
      await holder.query('SELECT pg_advisory_unlock($1::bigint)', [
        pinDurabilityLockKey(cid).toString(),
      ]);
      await holder.release();

      const result = await deleted;

      expect(result.unpinned).toBe(0);
      expect(pinStore.unpinned).toEqual([]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b.id]);
      expect(await db.dataSource.getRepository(User).findOne({ where: { id: a.id } })).toBeNull();
    });

    it('negative control — without the durability lock the post-commit unpin ignores the concurrent upload and removes a now-live CID', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const cid = token();
      await seedPin(a.id, cid);

      const pinStore = new RecordingPinStore();

      // The upload holds the durability lock, but the delete's post-commit lock
      // is stripped: it never waits, recounts before the upload's row is visible,
      // and unpins content B is about to own.
      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.query('SELECT pg_advisory_lock($1::bigint)', [
        pinDurabilityLockKey(cid).toString(),
      ]);

      const result = await deleteService(
        gatedDataSource(db.dataSource, { stripDurabilityLock: true }),
        pinStore
      ).deleteAccount(a.id);

      await seedPin(b.id, cid); // the upload's live pin row commits — too late
      await holder.query('SELECT pg_advisory_unlock($1::bigint)', [
        pinDurabilityLockKey(cid).toString(),
      ]);
      await holder.release();

      expect(result.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b.id]);
    });
  });

  describe('record_cache residue purge', () => {
    it('purges the account cache rows but spares a name another account co-owns', async () => {
      const a = await seedAccount();
      const b = await seedAccount();
      const own = token(); // IPNS name only A holds
      const shared = token(); // IPNS name A and B both hold
      await db.dataSource.getRepository(NameInventory).save([
        { accountId: a.id, ipnsName: own },
        { accountId: a.id, ipnsName: shared },
        { accountId: b.id, ipnsName: shared },
      ]);
      const cacheRepo = db.dataSource.getRepository(RecordCache);
      await cacheRepo.save([
        { ipnsName: own, record: Buffer.from('r1'), sequence: '1', lastRepublishedAt: null },
        { ipnsName: shared, record: Buffer.from('r2'), sequence: '1', lastRepublishedAt: null },
      ]);

      await deleteService(db.dataSource, new RecordingPinStore()).deleteAccount(a.id);

      // A's orphan cache row is gone; the co-owned name's row survives (B still
      // owns it — it repopulates next sweep regardless).
      expect(await cacheRepo.findOne({ where: { ipnsName: own } })).toBeNull();
      expect(await cacheRepo.findOne({ where: { ipnsName: shared } })).not.toBeNull();
      expect(
        await db.dataSource.getRepository(NameInventory).find({ where: { accountId: a.id } })
      ).toEqual([]);
    });
  });

  describe('per-call drain budget', () => {
    it('caps one call with a retryable 503 and a retry resumes to completion', async () => {
      const { id } = await seedAccount();
      await seedPin(id, token());

      // An adversarial client re-uploads a fresh pin against each chunk's
      // pre-read, so a single call can never observe zero pins. The per-call
      // budget must stop it with a 503; a retry (no re-seeding) then drains.
      let reseed = true;
      const realPinRepo = db.dataSource.getRepository(PinnedCid);
      const gatedPinRepo = new Proxy(realPinRepo, {
        get(target, prop, receiver) {
          if (prop === 'find') {
            return async (options?: unknown) => {
              const rows = await target.find(options as never);
              if (
                reseed &&
                (options as { take?: number })?.take === DELETE_CHUNK_SIZE &&
                (rows as unknown[]).length > 0
              ) {
                await seedPin(id, token());
              }
              return rows;
            };
          }
          const value = Reflect.get(target, prop, receiver);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }) as Repository<PinnedCid>;

      const pinStore = new RecordingPinStore();
      const service = new AccountService(
        db.dataSource.getRepository(User) as never,
        gatedPinRepo as never,
        db.dataSource as never,
        pinStore,
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
      );

      await expect(service.deleteAccount(id)).rejects.toBeInstanceOf(ServiceUnavailableException);
      // The account is NOT deleted — residue is left for the retry, never lost.
      expect(await db.dataSource.getRepository(User).findOne({ where: { id } })).not.toBeNull();

      reseed = false;
      const resumed = await service.deleteAccount(id);

      expect(resumed.pinsRetired).toBeGreaterThanOrEqual(1);
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { accountId: id } })
      ).toEqual([]);
      expect(await db.dataSource.getRepository(User).findOne({ where: { id } })).toBeNull();
    });
  });

  describe('auth-row cascade', () => {
    it('deletes the account auth_methods and refresh_tokens via the FK cascade', async () => {
      const { id } = await seedAccount();
      await db.dataSource
        .getRepository(AuthMethod)
        .save({ userId: id, kind: 'identity', identifierHash: token() });
      await db.dataSource.getRepository(RefreshToken).save({
        userId: id,
        familyId: '00000000-0000-0000-0000-000000000000',
        tokenHash: token(),
        expiresAt: new Date(Date.now() + 60_000),
      });

      await deleteService(db.dataSource, new RecordingPinStore()).deleteAccount(id);

      expect(await db.dataSource.getRepository(AuthMethod).count({ where: { userId: id } })).toBe(
        0
      );
      expect(await db.dataSource.getRepository(RefreshToken).count({ where: { userId: id } })).toBe(
        0
      );
    });
  });

  describe('mailbox-post resurrection window', () => {
    it('a post that raced the delete fails closed under the recipient lock and leaves no orphan row', async () => {
      const { id, publicKey } = await seedAccount();
      const sender = compressedPublicKey();

      // Pause the post right after its unlocked existence-oracle read, before it
      // takes the recipient lock — the exact gap the delete slips through.
      const gate = makeGate();
      const gatedUserRepo = new Proxy(db.dataSource.getRepository(User), {
        get(target, prop, receiver) {
          if (prop === 'findOne') {
            return async (options: FindOneOptions<User>) => {
              const row = await target.findOne(options);
              await gate.onReach();
              return row;
            };
          }
          const value = Reflect.get(target, prop, receiver);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      }) as Repository<User>;

      const posting = mailboxService(gatedUserRepo).post(sender, {
        recipientPublicKey: publicKey,
        blob: Buffer.from('sealed').toString('base64'),
        idempotencyKey: token(),
      });

      await gate.reached; // oracle saw the recipient; not yet under the lock
      await deleteService(db.dataSource, new RecordingPinStore()).deleteAccount(id);
      gate.release();

      // The in-lock existence re-check now sees a gone recipient → fail closed.
      await expect(posting).rejects.toBeInstanceOf(NotFoundException);
      expect(await db.dataSource.getRepository(MailboxMessage).count()).toBe(0);
    });

    it('the residue delete serializes on the recipient lock a mailbox post holds', async () => {
      const { id, publicKey } = await seedAccount();

      // Hold the recipient advisory key the mailbox POST takes across its
      // existence re-check → insert. The residue delete must block on it — proof
      // it serializes with a concurrent post rather than racing it to an orphan.
      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.startTransaction();
      await holder.query('SELECT pg_advisory_xact_lock($1::bigint)', [
        advisoryLockKey(publicKey).toString(),
      ]);

      let deleteDone = false;
      const deleted = deleteService(db.dataSource, new RecordingPinStore())
        .deleteAccount(id)
        .then((r) => {
          deleteDone = true;
          return r;
        });

      await waitForAdvisoryLockWait(db.dataSource);
      expect(deleteDone).toBe(false);

      await holder.rollbackTransaction();
      await holder.release();
      await deleted;

      expect(await db.dataSource.getRepository(User).findOne({ where: { id } })).toBeNull();
    });

    it('negative control — with an existence check that never reflects the deletion, the raced post resurrects an orphan mailbox row', async () => {
      const { id, publicKey } = await seedAccount();
      const sender = compressedPublicKey();
      const staleUser = await db.dataSource.getRepository(User).findOne({ where: { id } });

      // A user repo that ALWAYS reports the recipient present (never reflecting
      // the deletion) and pauses on its first read — simulating the pre-fix path
      // where nothing in the serialized window observed the committed delete.
      const gate = makeGate();
      let firstRead = true;
      const staleRepo = {
        findOne: async () => {
          if (firstRead) {
            firstRead = false;
            await gate.onReach();
          }
          return staleUser;
        },
      } as unknown as Repository<User>;

      const posting = mailboxService(staleRepo).post(sender, {
        recipientPublicKey: publicKey,
        blob: Buffer.from('sealed').toString('base64'),
        idempotencyKey: token(),
      });

      await gate.reached;
      await deleteService(db.dataSource, new RecordingPinStore()).deleteAccount(id);
      gate.release();

      // With the re-check unable to see the deletion, the post inserts a row for
      // the deleted account — the orphan the real re-check closes.
      await posting;
      expect(await db.dataSource.getRepository(MailboxMessage).count()).toBe(1);
    });
  });

  describe('lock-timeout maps to 503', () => {
    it('a delete whose users-row lock waits past lock_timeout surfaces a retryable 503, not a 500', async () => {
      const { id } = await seedAccount();

      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.startTransaction();
      await holder.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [id]);

      try {
        await expect(
          deleteService(db.dataSource, new RecordingPinStore(), '200').deleteAccount(id)
        ).rejects.toBeInstanceOf(ServiceUnavailableException);
      } finally {
        await holder.rollbackTransaction();
        await holder.release();
      }
    });
  });
});
