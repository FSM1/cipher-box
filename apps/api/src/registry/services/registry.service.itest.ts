import { ServiceUnavailableException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { DataSource, EntityManager, FindManyOptions, FindOneOptions, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { pinDurabilityLockKey, withSessionAdvisoryLock } from '../../common/advisory-lock';
import { fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { RegistryService } from './registry.service';

/**
 * The registry's per-token advisory-lock invariants proven on a REAL Postgres:
 * BYO-flag serialization, the register-vs-retire premature-unpin phantom, and
 * concurrent duplicate inserts. Real row/advisory locks are genuine Postgres
 * behavior no in-memory fake can exercise, so these live in the real-Postgres
 * integration suite. Each interleaving test pins the lock's effect with a
 * negative control that reproduces the failure once the lock is stripped.
 */

function compressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

/** A random opaque token — stands in for an IPNS name or a content CID. */
function token(): string {
  return randomBytes(16).toString('hex');
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

function pgErrorCode(error: unknown): string | undefined {
  const e = error as { code?: string; driverError?: { code?: string } } | undefined;
  return e?.driverError?.code ?? e?.code;
}

/** Records the CIDs a retire physically unpins, so premature unpins are observable. */
class RecordingPinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

/** Records the unpin, then pauses inside it so a test can commit a racing row. */
class GatedUnpinStore extends RecordingPinStore {
  constructor(private readonly gate: Gate) {
    super();
  }
  override async unpin(cid: string): Promise<boolean> {
    const released = await super.unpin(cid);
    await this.gate.onReach();
    return released;
  }
}

/** A barrier a gated transaction trips the instant it reaches its hook point. */
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
  /** No-op the advisory lock + lock_timeout, and drop the users-row lock — the pre-#677 path. */
  stripLock?: boolean;
  /** No-op the post-commit SESSION advisory lock — the pre-#714 unguarded-unpin path. */
  stripSessionLock?: boolean;
  afterUserRead?: () => Promise<void>;
  afterPinFind?: () => Promise<void>;
  afterPinInsert?: () => Promise<void>;
}

/**
 * A DataSource that runs the real transaction but can strip the locks and pause
 * at chosen points, so a concurrent operation can be observed to block (lock
 * present) or to race (lock stripped).
 */
function gatedDataSource(real: DataSource, hooks: GateHooks): DataSource {
  const wrapUserRepo = (repo: Repository<User>): Repository<User> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'findOne') {
          return async (options: FindOneOptions<User>) => {
            const opts = hooks.stripLock ? { ...options, lock: undefined } : options;
            const row = await target.findOne(opts);
            if (hooks.afterUserRead) await hooks.afterUserRead();
            return row;
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

  const wrapPinRepo = (repo: Repository<PinnedCid>): Repository<PinnedCid> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'find') {
          return async (options?: FindManyOptions<PinnedCid>) => {
            const rows = await target.find(options);
            if (hooks.afterPinFind) await hooks.afterPinFind();
            return rows;
          };
        }
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

  // Strip the SESSION advisory (un)lock the post-commit unpin guard takes on a
  // dedicated runner, so retire's recount races the concurrent upload instead of
  // serializing behind it — the pre-#714 unguarded-unpin path.
  const wrapQueryRunner = (runner: ReturnType<DataSource['createQueryRunner']>) =>
    new Proxy(runner, {
      get(target, prop, receiver) {
        if (prop === 'query') {
          return async (sql: string, params?: unknown[]) => {
            if (/pg_advisory_lock|pg_advisory_unlock/i.test(sql)) {
              return [];
            }
            return target.query(sql, params);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

  return {
    createQueryRunner: () => {
      const runner = real.createQueryRunner();
      return hooks.stripSessionLock ? wrapQueryRunner(runner) : runner;
    },
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
  } as unknown as DataSource;
}

describe('RegistryService concurrency (real Postgres)', () => {
  let db: IntegrationDatabase;

  beforeAll(async () => {
    // Room for a held gated transaction plus its racing partner.
    db = await createIntegrationDatabase({ poolMax: 10 });
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  // The lock timeout is disabled in these interleaving tests so the gate — not
  // the wall clock — controls when a blocked operation proceeds; the timeout's
  // own effect is proven in advisory-lock.itest.ts.
  function buildService(ds: DataSource, pinStore: PinStore): RegistryService {
    return new RegistryService(
      db.dataSource.getRepository(PinnedCid) as never,
      db.dataSource.getRepository(User) as never,
      ds as never,
      pinStore,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
    );
  }

  async function seedAccount(byo: boolean): Promise<string> {
    const user = await db.dataSource
      .getRepository(User)
      .save({ publicKey: compressedPublicKey(), byo });
    return user.id;
  }

  async function seedPin(accountId: string, cid: string): Promise<void> {
    await db.dataSource
      .getRepository(PinnedCid)
      .save({ accountId, cid, size: '0', advisory: false });
  }

  async function pinsFor(accountId: string): Promise<PinnedCid[]> {
    return db.dataSource.getRepository(PinnedCid).find({ where: { accountId } });
  }

  describe('BYO-flag serialization', () => {
    it('a concurrent setByo blocks while register holds the users-row lock; the new pin row keeps the value read under the lock', async () => {
      const accountId = await seedAccount(false);
      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      const register = buildService(
        gatedDataSource(db.dataSource, { afterUserRead: gate.onReach }),
        pinStore
      );

      const registered = register.register(accountId, [
        { ipnsName: token(), contentCids: [token()] },
      ]);

      // register has taken the row lock and read byo=false; it now waits, still
      // holding the lock and uncommitted.
      await gate.reached;

      let setByoDone = false;
      const toggled = buildService(db.dataSource, pinStore)
        .setByo(accountId, true)
        .then((result) => {
          setByoDone = true;
          return result;
        });

      // The toggle is blocked on register's row lock — it cannot commit.
      await delay(200);
      expect(setByoDone).toBe(false);

      gate.release();
      const result = await registered;
      const toggleResult = await toggled;

      expect(setByoDone).toBe(true);
      expect(result).toEqual({ names: 1, cids: 1 });
      expect(toggleResult).toEqual({ byo: true });

      // The pin row carries advisory=false — register's locked read — and the
      // toggle applied strictly after register committed.
      const pins = await pinsFor(accountId);
      expect(pins).toHaveLength(1);
      expect(pins[0].advisory).toBe(false);
      const user = await db.dataSource.getRepository(User).findOne({ where: { id: accountId } });
      expect(user?.byo).toBe(true);
    });

    it('negative control — without the row lock, setByo commits between the read and the insert, tearing the advisory stamp', async () => {
      const accountId = await seedAccount(false);
      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      // Same interleaving, but the users read drops the pessimistic lock (the
      // pre-fix code path) — nothing serializes register against the toggle.
      const register = buildService(
        gatedDataSource(db.dataSource, { stripLock: true, afterUserRead: gate.onReach }),
        pinStore
      );

      const registered = register.register(accountId, [
        { ipnsName: token(), contentCids: [token()] },
      ]);
      await gate.reached;

      // With no row lock, the toggle commits immediately, mid-register.
      await buildService(db.dataSource, pinStore).setByo(accountId, true);
      const midUser = await db.dataSource.getRepository(User).findOne({ where: { id: accountId } });
      expect(midUser?.byo).toBe(true);

      gate.release();
      await registered;

      // The pin row is stamped advisory=false — the stale pre-toggle read — even
      // though the account is now BYO. This is the race the row lock closes.
      const pins = await pinsFor(accountId);
      expect(pins).toHaveLength(1);
      expect(pins[0].advisory).toBe(false);
    });
  });

  describe('register-vs-retire phantom', () => {
    it('a register committing under the lock keeps the CID pinned; retire finds the survivor and does not unpin', async () => {
      const a = await seedAccount(false);
      const b = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid);

      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      const registerB = buildService(
        gatedDataSource(db.dataSource, { afterPinInsert: gate.onReach }),
        pinStore
      ).register(b, [{ ipnsName: token(), contentCids: [cid] }]);

      // register(B) has inserted its (B, cid) pin and paused, still holding the
      // advisory lock and uncommitted.
      await gate.reached;

      let retireDone = false;
      const retired = buildService(db.dataSource, pinStore)
        .retire(a, [cid])
        .then((r) => {
          retireDone = true;
          return r;
        });

      // retire is blocked on register(B)'s advisory lock — it cannot reach its
      // survivor check, let alone unpin.
      await delay(200);
      expect(retireDone).toBe(false);
      expect(pinStore.unpinned).toEqual([]);

      gate.release();
      await registerB;
      const result = await retired;

      // retire ran after register(B) committed, saw the surviving (B, cid), and
      // did NOT unpin.
      expect(retireDone).toBe(true);
      expect(result.unpinned).toBe(0);
      expect(pinStore.unpinned).toEqual([]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b]);
    });

    it('negative control — without the advisory lock, retire prematurely unpins a CID a concurrent register is adding', async () => {
      const a = await seedAccount(false);
      const b = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid);

      const gate = makeGate();
      const pinStore = new RecordingPinStore();
      // Both paths skip the advisory lock (the pre-#677 code path).
      const registerB = buildService(
        gatedDataSource(db.dataSource, { stripLock: true, afterPinInsert: gate.onReach }),
        pinStore
      ).register(b, [{ ipnsName: token(), contentCids: [cid] }]);

      await gate.reached; // (B, cid) inserted but uncommitted

      // With no lock, retire runs concurrently: it deletes A's row and its
      // survivor check cannot see B's uncommitted insert, so it unpins the CID.
      const retireResult = await buildService(
        gatedDataSource(db.dataSource, { stripLock: true }),
        pinStore
      ).retire(a, [cid]);

      gate.release();
      await registerB;

      // The CID was physically unpinned even though B now holds it — the
      // premature unpin the advisory lock closes.
      expect(retireResult.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b]);
    });
  });

  describe('user-row lock timeout maps to 503', () => {
    it('a register whose users-row lock waits past lock_timeout surfaces a retryable 503, not a 500', async () => {
      const accountId = await seedAccount(false);

      // The transaction-scoped lock_timeout bounds the advisory acquire AND the
      // users-row pessimistic_write taken later. Hold that row locked elsewhere
      // so register's wait aborts with 55P03 — which must map to 503, not 500.
      const holder = db.dataSource.createQueryRunner();
      await holder.connect();
      await holder.startTransaction();
      await holder.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [accountId]);

      const service = new RegistryService(
        db.dataSource.getRepository(PinnedCid) as never,
        db.dataSource.getRepository(User) as never,
        db.dataSource as never,
        new RecordingPinStore(),
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '200' }).service
      );

      try {
        await expect(
          service.register(accountId, [{ ipnsName: token(), contentCids: [token()] }])
        ).rejects.toBeInstanceOf(ServiceUnavailableException);
      } finally {
        await holder.rollbackTransaction();
        await holder.release();
      }
    });
  });

  describe('concurrent duplicate insert', () => {
    it('two concurrent registers of the same CID insert exactly one pin row; the lock serializes the second into an idempotent skip', async () => {
      const a = await seedAccount(false);
      const cid = token();
      const gate = makeGate();
      const pinStore = new RecordingPinStore();

      const first = buildService(
        gatedDataSource(db.dataSource, { afterPinFind: gate.onReach }),
        pinStore
      ).register(a, [{ ipnsName: token(), contentCids: [cid] }]);

      // first read its (empty) existing-pins set under the lock, then paused.
      await gate.reached;

      let secondDone = false;
      const second = buildService(db.dataSource, pinStore)
        .register(a, [{ ipnsName: token(), contentCids: [cid] }])
        .then((r) => {
          secondDone = true;
          return r;
        });

      // second is blocked at the advisory lock the first still holds.
      await delay(200);
      expect(secondDone).toBe(false);

      gate.release();
      await expect(first).resolves.toEqual({ names: 1, cids: 1 });
      await expect(second).resolves.toEqual({ names: 1, cids: 1 });

      const pins = await db.dataSource
        .getRepository(PinnedCid)
        .find({ where: { accountId: a, cid } });
      expect(pins).toHaveLength(1);
    });

    it('negative control — without the lock, two concurrent registers both read empty and collide on the unique index (23505)', async () => {
      const a = await seedAccount(false);
      const cid = token();
      const gate = makeGate();
      const pinStore = new RecordingPinStore();

      // Strip the serialization (advisory lock + the incidental users-row lock)
      // so both registers pass the existence check before either inserts.
      const first = buildService(
        gatedDataSource(db.dataSource, { stripLock: true, afterPinFind: gate.onReach }),
        pinStore
      ).register(a, [{ ipnsName: token(), contentCids: [cid] }]);

      // first read existing-pins (empty) and paused before its insert.
      await gate.reached;

      // second runs fully: it also sees no existing pin and inserts (a, cid).
      await buildService(gatedDataSource(db.dataSource, { stripLock: true }), pinStore).register(
        a,
        [{ ipnsName: token(), contentCids: [cid] }]
      );

      // first now inserts the same (a, cid) and hits the unique violation.
      gate.release();
      let caught: unknown;
      try {
        await first;
      } catch (error) {
        caught = error;
      }
      expect(pgErrorCode(caught)).toBe('23505');
    });
  });

  describe('retire post-commit unpin guard (#714)', () => {
    it('at true global-zero the guarded unpin fires exactly once', async () => {
      const a = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid);

      const pinStore = new RecordingPinStore();
      const result = await buildService(db.dataSource, pinStore).retire(a, [cid]);

      expect(result.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      expect(await db.dataSource.getRepository(PinnedCid).find({ where: { cid } })).toEqual([]);
    });

    it('skips the unpin when a concurrent upload re-pins the CID inside the commit→unpin window', async () => {
      const a = await seedAccount(false);
      const b = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid); // A is the sole holder — retire will decide to unpin.

      // A concurrent upload holds the SAME pin-durability session lock the guard
      // takes and, while holding it, commits a fresh size>0 pin row for the CID —
      // the re-pin retire's lagging unpin would otherwise destroy.
      const gate = makeGate();
      const uploadPromise = withSessionAdvisoryLock(
        db.dataSource,
        pinDurabilityLockKey(cid),
        0,
        async () => {
          await gate.onReach();
          await db.dataSource
            .getRepository(PinnedCid)
            .save({ accountId: b, cid, size: '100', advisory: false });
        }
      );
      await gate.reached; // upload holds the session lock; B's row not yet inserted

      // retire(A): its txn deletes A's only row, sees no survivor, commits, then
      // BLOCKS acquiring the pin-durability lock the upload still holds.
      const pinStore = new RecordingPinStore();
      let retireDone = false;
      const retired = buildService(db.dataSource, pinStore)
        .retire(a, [cid])
        .then((r) => {
          retireDone = true;
          return r;
        });

      await delay(200);
      expect(retireDone).toBe(false);
      expect(pinStore.unpinned).toEqual([]);

      gate.release(); // upload commits B's row and releases the session lock
      await uploadPromise;
      const result = await retired;

      // retire acquired the lock, recounted, saw B's survivor, and SKIPPED the
      // unpin — the freshly-pinned bytes are preserved.
      expect(result.unpinned).toBe(0);
      expect(pinStore.unpinned).toEqual([]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b]);
    });

    it('a contended durability lock leaves the CID pinned for GC and still reports the committed retire, not a 503', async () => {
      const a = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid); // A is the sole holder — retire will decide to unpin.

      // Hold the SAME pin-durability session lock so retire's post-commit acquire
      // waits past lock_timeout and aborts (55P03) — the contention this test
      // proves must degrade to a skip, not fail the already-committed retire.
      const gate = makeGate();
      const holder = withSessionAdvisoryLock(
        db.dataSource,
        pinDurabilityLockKey(cid),
        0,
        async () => {
          await gate.onReach();
        }
      );
      await gate.reached; // the durability lock is held

      const pinStore = new RecordingPinStore();
      const service = new RegistryService(
        db.dataSource.getRepository(PinnedCid) as never,
        db.dataSource.getRepository(User) as never,
        db.dataSource as never,
        pinStore,
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '200' }).service
      );

      // retire's delete commits; the post-commit unpin can't acquire the held
      // durability lock within 200ms, so it skips the unpin and returns.
      const result = await service.retire(a, [cid]);

      gate.release();
      await holder;

      expect(result).toEqual({ retired: 1, unpinned: 0 });
      expect(pinStore.unpinned).toEqual([]);
      // The row is gone (retire committed) but the CID is left pinned for GC.
      expect(await db.dataSource.getRepository(PinnedCid).find({ where: { cid } })).toEqual([]);
    });

    it('negative control — with the session lock stripped, retire prematurely unpins a CID a concurrent upload re-pins', async () => {
      const a = await seedAccount(false);
      const b = await seedAccount(false);
      const cid = token();
      await seedPin(a, cid);

      // The unpin is gated so the racing upload can commit its row DURING it,
      // after retire's now-unserialized recount has already passed.
      const gate = makeGate();
      const pinStore = new GatedUnpinStore(gate);
      const retired = buildService(
        gatedDataSource(db.dataSource, { stripSessionLock: true }),
        pinStore
      ).retire(a, [cid]);

      // retire committed, recounted (no survivor), and is now paused inside unpin.
      await gate.reached;
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: b, cid, size: '100', advisory: false });

      gate.release();
      const result = await retired;

      // The CID was physically unpinned even though B now holds it — the
      // data-loss window the session-lock guard closes.
      expect(result.unpinned).toBe(1);
      expect(pinStore.unpinned).toEqual([cid]);
      const survivors = await db.dataSource.getRepository(PinnedCid).find({ where: { cid } });
      expect(survivors.map((r) => r.accountId)).toEqual([b]);
    });
  });
});
