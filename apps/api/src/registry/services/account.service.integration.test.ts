import { NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { DataSource, EntityManager, FindOneOptions, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuthMethod } from '../../auth/entities/auth-method.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import { pinDurabilityLockKey } from '../../common/advisory-lock';
import { MailboxMessage } from '../../mailbox/entities/mailbox-message.entity';
import { MailboxService } from '../../mailbox/services/mailbox.service';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { RegistryService } from './registry.service';
import { AccountService } from './account.service';

/**
 * The account hard-delete cascade proven on a REAL Postgres: the refcount unpin
 * across the delete/register phantom, the mailbox-post resurrection window, the
 * auth-row cascade, co-registered survival, and the lock-timeout 503. Real
 * row/advisory locks and FK cascades are genuine Postgres behavior no in-memory
 * fake can exercise. Each interleaving test pins the lock/re-check effect with a
 * negative control that reproduces the failure once the guard is stripped.
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
  afterPinSave?: () => Promise<void>;
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
        if (prop === 'save') {
          return async (entities: never, options?: never) => {
            const saved = await target.save(entities, options);
            if (hooks.afterPinSave) await hooks.afterPinSave();
            return saved;
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
    await db.dataSource.query('TRUNCATE TABLE users, mailbox_messages CASCADE');
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
        gatedDataSource(db.dataSource, { afterPinSave: gate.onReach }),
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
      // survivor check, let alone unpin.
      await delay(200);
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
        gatedDataSource(db.dataSource, { stripLock: true, afterPinSave: gate.onReach }),
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

    it('fails closed (retryable 503) when a pin commits into the unlocked pre-read gap, never deleting it unpinned', async () => {
      const a = await seedAccount();
      const cid = token();

      // Pause the delete's UNLOCKED pre-read; a pin then commits into the gap
      // before the delete takes its account-lock batch — the exact phantom the
      // in-lock re-read closes.
      const gate = makeGate();
      let firstFind = true;
      const pinRepo = db.dataSource.getRepository(PinnedCid);
      const gatedPinRepo = new Proxy(pinRepo, {
        get(target, prop, receiver) {
          if (prop === 'find') {
            return async (options?: unknown) => {
              const rows = await target.find(options as never);
              if (firstFind) {
                firstFind = false;
                await gate.onReach();
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

      const deleted = service.deleteAccount(a.id);
      await gate.reached; // pre-read observed no pins; still before the lock batch
      await seedPin(a.id, cid); // a pin commits into the gap, unlocked by the batch
      gate.release();

      await expect(deleted).rejects.toBeInstanceOf(ServiceUnavailableException);

      // Fail-closed: the raced pin's row is intact (never deleted unpinned) and
      // the account survives, so the client's retry unpins it at refcount zero.
      expect(pinStore.unpinned).toEqual([]);
      const rows = await db.dataSource
        .getRepository(PinnedCid)
        .find({ where: { accountId: a.id } });
      expect(rows.map((r) => r.cid)).toEqual([cid]);
      expect(
        await db.dataSource.getRepository(User).findOne({ where: { id: a.id } })
      ).not.toBeNull();
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

      await delay(200); // delete has committed and is blocked on the durability lock
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
