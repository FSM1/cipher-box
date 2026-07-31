import {
  ConflictException,
  PayloadTooLargeException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import { DataSource, EntityManager, FindOneOptions, QueryRunner, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { advisoryLockKey } from '../common/advisory-lock';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { PinCidMismatchError, PinStore } from '../registry/pin-store';
import { RegistryService } from '../registry/services/registry.service';
import { fakeConfig } from '../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { ContentService, UploadResult } from './content.service';

/**
 * The hosted upload path's two concurrency guards + the quota/atomicity
 * invariants, proven on a REAL Postgres where genuine advisory locks and the
 * numeric SUM behave as they cannot under an in-memory fake. Each guard is
 * pinned by a negative control that reproduces the breach once the guard is
 * stripped.
 */

function compressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/** Deterministic CID from bytes; declared and actual agree unless a test deliberately mismatches. */
class FakePinStore extends PinStore {
  readonly pinned: string[] = [];
  readonly unpinned: string[] = [];
  failPin = false;
  /** When set, pin() reaches this gate (after commit) and waits before resolving. */
  pinGate?: Gate;

  cidFor(bytes: Uint8Array): string {
    return `ba${createHash('sha256').update(bytes).digest('hex')}`;
  }

  override async pin(cid: string, bytes: Uint8Array): Promise<void> {
    if (this.pinGate) {
      await this.pinGate.onReach();
    }
    if (this.failPin) {
      throw new Error('pin store unavailable');
    }
    const actual = this.cidFor(bytes);
    if (actual !== cid) {
      throw new PinCidMismatchError(cid, actual);
    }
    this.pinned.push(cid);
  }

  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
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
  /** Skip these advisory-lock keys' acquires — models removing a guard. */
  skipLockKeys?: bigint[];
  /** Pause right before the pin-row INSERT (after the quota gate has decided). */
  beforeInsert?: () => Promise<void>;
  /** Drop the users-row FOR UPDATE lock — models the pre-fix unlocked BYO read. */
  stripUserLock?: boolean;
  /** Pause right after the users-row read (BYO already read under the lock). */
  afterUserRead?: () => Promise<void>;
}

/**
 * A DataSource that runs the real transaction but can drop chosen advisory locks
 * and pause before the insert, so a concurrent upload can be observed to block
 * (lock present) or to race (lock removed). Skipping applies to BOTH the in-tx
 * xact locks and the session lock taken on a dedicated query runner.
 */
function gatedDataSource(real: DataSource, hooks: GateHooks): DataSource {
  const skip = new Set((hooks.skipLockKeys ?? []).map((k) => k.toString()));
  // The session lock/unlock (pg_advisory_lock / pg_advisory_unlock) — NOT the
  // xact variant (pg_advisory_xact_lock) — dropped when its key is skipped.
  const wrapRunner = (runner: QueryRunner): QueryRunner =>
    new Proxy(runner, {
      get(target, prop, receiver) {
        if (prop === 'query') {
          return async (sql: string, params?: unknown[]) => {
            if (/pg_advisory_(?:un)?lock\(/i.test(sql) && skip.has(String(params?.[0]))) {
              return [];
            }
            return target.query(sql, params);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function'
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
  const wrapUserRepo = (repo: Repository<User>): Repository<User> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'findOne') {
          return async (options: FindOneOptions<User>) => {
            const opts = hooks.stripUserLock ? { ...options, lock: undefined } : options;
            const row = await target.findOne(opts);
            if (hooks.afterUserRead) await hooks.afterUserRead();
            return row;
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function'
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });
  const wrapPinRepo = (repo: Repository<PinnedCid>): Repository<PinnedCid> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'insert') {
          return async (entity: never) => {
            if (hooks.beforeInsert) await hooks.beforeInsert();
            return target.insert(entity);
          };
        }
        const value = Reflect.get(target, prop, receiver);
        return typeof value === 'function'
          ? (value as (...a: unknown[]) => unknown).bind(target)
          : value;
      },
    });

  return {
    createQueryRunner: () => wrapRunner(real.createQueryRunner()),
    transaction: (runInTransaction: (manager: EntityManager) => Promise<unknown>) =>
      real.transaction((manager) => {
        const proxied = new Proxy(manager, {
          get(target, prop, receiver) {
            if (prop === 'query') {
              return async (sql: string, params?: unknown[]) => {
                // The batch helper acquires all keys in one round-trip via
                // `unnest($1::bigint[])`, so drop skipped keys FROM the array and
                // acquire the rest; return [] only if every key was skipped.
                if (/pg_advisory_xact_lock/i.test(sql) && Array.isArray(params?.[0])) {
                  const kept = (params[0] as unknown[]).filter((k) => !skip.has(String(k)));
                  if (kept.length === 0) {
                    return [];
                  }
                  return target.query(sql, [kept]);
                }
                if (/pg_advisory_xact_lock/i.test(sql) && skip.has(String(params?.[0]))) {
                  return [];
                }
                return target.query(sql, params);
              };
            }
            if (prop === 'getRepository') {
              return (entity: unknown) => {
                const repo = target.getRepository(entity as never);
                if (entity === PinnedCid) return wrapPinRepo(repo as Repository<PinnedCid>);
                if (entity === User) return wrapUserRepo(repo as Repository<User>);
                return repo;
              };
            }
            const value = Reflect.get(target, prop, receiver);
            return typeof value === 'function'
              ? (value as (...a: unknown[]) => unknown).bind(target)
              : value;
          },
        });
        return runInTransaction(proxied);
      }),
  } as unknown as DataSource;
}

function accountLockKey(accountId: string): bigint {
  return advisoryLockKey(`account:${accountId}`);
}

function pinDurabilityLockKey(cid: string): bigint {
  return advisoryLockKey(`pin-durability:${cid}`);
}

describe('ContentService upload concurrency (real Postgres)', () => {
  let db: IntegrationDatabase;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  // Lock timeout disabled: the gate, not the wall clock, decides when a blocked
  // upload proceeds. The timeout's own effect is proven in advisory-lock tests.
  function buildService(
    ds: DataSource,
    pinStore: PinStore,
    config: Record<string, string> = {}
  ): ContentService {
    return new ContentService(
      ds as never,
      pinStore,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0', ...config }).service
    );
  }

  async function seedAccount(overrides: Partial<User> = {}): Promise<string> {
    const user = await db.dataSource
      .getRepository(User)
      .save({ publicKey: compressedPublicKey(), byo: false, ...overrides });
    return user.id;
  }

  async function pinsFor(accountId: string): Promise<PinnedCid[]> {
    return db.dataSource.getRepository(PinnedCid).find({ where: { accountId } });
  }

  async function usedBytes(accountId: string): Promise<bigint> {
    const rows = await pinsFor(accountId);
    return rows.reduce((total, row) => total + BigInt(row.size), 0n);
  }

  describe('quota gate — per-account advisory lock', () => {
    it('serializes two same-account uploads at the limit: exactly one is admitted, the other refused', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '100' });
      const gate = makeGate();
      const pinStore = new FakePinStore();
      const firstBytes = Buffer.alloc(60, 1);
      const secondBytes = Buffer.alloc(60, 2);

      const first = buildService(
        gatedDataSource(db.dataSource, { beforeInsert: gate.onReach }),
        pinStore
      ).upload(accountId, pinStore.cidFor(firstBytes), firstBytes);

      // first holds the account lock, passed the gate (used 0 + 60 <= 100), and
      // paused just before its insert.
      await gate.reached;

      let secondDone = false;
      const second = buildService(db.dataSource, pinStore)
        .upload(accountId, pinStore.cidFor(secondBytes), secondBytes)
        .then((r) => {
          secondDone = true;
          return r;
        })
        .catch((e: unknown) => {
          secondDone = true;
          throw e;
        });

      // second is blocked acquiring the account lock first still holds.
      await delay(200);
      expect(secondDone).toBe(false);

      gate.release();
      await expect(first).resolves.toMatchObject({ size: 60 });
      // second wakes, reads used=60, and 60+60 > 100 is refused.
      await expect(second).rejects.toBeInstanceOf(PayloadTooLargeException);

      expect(await pinsFor(accountId)).toHaveLength(1);
      expect(await usedBytes(accountId)).toBe(60n);
    });

    it('negative control — with both account serializers removed, both uploads pass the stale sum and breach the quota', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '100' });
      const skipLockKey = accountLockKey(accountId);
      const gate = makeGate();
      const pinStore = new FakePinStore();

      // Both uploads skip the account advisory lock AND the users-row lock (the
      // two per-account serializers); their CIDs differ, so the CID lock never
      // serializes them either — nothing does.
      const gateHooks = { skipLockKeys: [skipLockKey], stripUserLock: true };
      const firstBytes = Buffer.alloc(60, 1);
      const secondBytes = Buffer.alloc(60, 2);
      const first = buildService(
        gatedDataSource(db.dataSource, { ...gateHooks, beforeInsert: gate.onReach }),
        pinStore
      ).upload(accountId, pinStore.cidFor(firstBytes), firstBytes);

      await gate.reached; // first read used=0, passed the gate, paused before insert

      // second runs fully with no account serializer: it also reads used=0 and inserts.
      await buildService(gatedDataSource(db.dataSource, gateHooks), pinStore).upload(
        accountId,
        pinStore.cidFor(secondBytes),
        secondBytes
      );

      gate.release();
      await first;

      // Both were admitted at the same 100-byte limit — a 120-byte over-quota
      // breach the per-account serialization closes.
      expect(await pinsFor(accountId)).toHaveLength(2);
      expect(await usedBytes(accountId)).toBe(120n);
    });
  });

  describe('per-CID pin row — advisory lock', () => {
    it('serializes two same-account uploads of the same CID into exactly one pin row (idempotent, charged once)', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(40, 7);
      const gate = makeGate();
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      const first = buildService(
        gatedDataSource(db.dataSource, { beforeInsert: gate.onReach }),
        pinStore
      ).upload(accountId, cid, bytes);

      await gate.reached;

      let secondDone = false;
      const second = buildService(db.dataSource, pinStore)
        .upload(accountId, cid, bytes)
        .then((r) => {
          secondDone = true;
          return r;
        });

      // second is blocked at the shared account/CID locks first holds.
      await delay(200);
      expect(secondDone).toBe(false);

      gate.release();
      await expect(first).resolves.toMatchObject({ size: 40 });
      // second wakes, finds first's committed row, and is an idempotent no-op.
      await expect(second).resolves.toMatchObject({ size: 40 });

      expect(await pinsFor(accountId)).toHaveLength(1);
      expect(await usedBytes(accountId)).toBe(40n); // charged once, not 80
    });

    it('negative control — without the locks, two concurrent same-CID uploads collide on the unique index (23505)', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(40, 7);
      const cid = new FakePinStore().cidFor(bytes);
      const skipKeys = [accountLockKey(accountId), advisoryLockKey(cid), pinDurabilityLockKey(cid)];
      const gate = makeGate();
      const pinStore = new FakePinStore();

      // Strip the account, CID, and durability advisory locks AND the users-row
      // lock (all distinct), so nothing serializes the two identical (account,
      // cid) inserts.
      const skipHooks = { skipLockKeys: skipKeys, stripUserLock: true };
      const first = buildService(
        gatedDataSource(db.dataSource, { ...skipHooks, beforeInsert: gate.onReach }),
        pinStore
      ).upload(accountId, cid, bytes);

      await gate.reached; // first found no existing row and paused before insert

      // second runs fully with no locks: it also sees no existing row and inserts.
      const secondResult = await buildService(gatedDataSource(db.dataSource, skipHooks), pinStore)
        .upload(accountId, cid, bytes)
        .catch((e: unknown) => e);

      // first now inserts the duplicate (account, cid) and hits the unique index.
      gate.release();
      const firstResult = await first.catch((e: unknown) => e);

      const errors = [firstResult, secondResult].filter((r) => r instanceof Error) as {
        driverError?: { code?: string };
        code?: string;
      }[];
      expect(errors.length).toBeGreaterThanOrEqual(1);
      const codes = errors.map((e) => e.driverError?.code ?? e.code);
      expect(codes).toContain('23505');
    });
  });

  describe('quota gate — BigInt exactness above 2^53', () => {
    it('refuses an upload a Number comparison would wrongly admit', async () => {
      // A limit and existing use far above 2^53, where a JS number cannot tell
      // `limit` from `limit + 1` (folded from #677).
      const limit = (1n << 60n) + 1n;
      const accountId = await seedAccount({ quotaLimitOverride: limit.toString() });
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId, cid: 'baExistingHuge', size: limit.toString(), advisory: false });

      // A Number-based gate would admit this (Number(used) + 1 rounds back to
      // Number(limit)); the BigInt gate refuses it.
      expect(Number(limit) + 1 <= Number(limit)).toBe(true);

      const pinStore = new FakePinStore();
      const bytes = Buffer.alloc(1, 9);
      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, pinStore.cidFor(bytes), bytes)
      ).rejects.toBeInstanceOf(PayloadTooLargeException);

      // Nothing was pinned; the ledger is unchanged.
      expect(pinStore.pinned).toEqual([]);
      expect(await usedBytes(accountId)).toBe(limit);
    });
  });

  describe('quota gate — scoped to authoritative (advisory=false) rows', () => {
    it('does not count advisory/BYO rows against the hosted quota (no false 413)', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '100' });
      // A stale advisory row an account kept after toggling BYO off, far over
      // the limit — its bytes live on the user's own provider, not the quota.
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId, cid: 'baAdvisoryStale', size: '500', advisory: true });

      const pinStore = new FakePinStore();
      const bytes = Buffer.alloc(60, 1);
      const result = await buildService(db.dataSource, pinStore).upload(
        accountId,
        pinStore.cidFor(bytes),
        bytes
      );

      expect(result.size).toBe(60);
      // Only the new authoritative row counts; the advisory 500 bytes are excluded.
      const authoritative = (await pinsFor(accountId)).filter((row) => !row.advisory);
      expect(authoritative).toHaveLength(1);
      expect(authoritative[0].size).toBe('60');
    });

    it('still 413s a genuine hosted-over-quota upload (authoritative rows do count)', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '100' });
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId, cid: 'baHosted', size: '60', advisory: false });

      const pinStore = new FakePinStore();
      const bytes = Buffer.alloc(60, 2);
      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, pinStore.cidFor(bytes), bytes)
      ).rejects.toBeInstanceOf(PayloadTooLargeException);
      // Nothing pinned; the authoritative 60 + incoming 60 > 100 refused.
      expect(pinStore.pinned).toEqual([]);
    });
  });

  // A BYO account's bytes live on its own provider and bypass the API
  // (blueprint/api.md, Content plane; #701). Hosted ingress must refuse it — a
  // 409 with NO pin and NO row — never pin to hosted Kubo off an advisory,
  // uncounted row (which would be unbounded free hosted storage).
  describe('hosted ingress refuses a BYO account', () => {
    it('rejects the upload with 409 and pins nothing, leaving no uncounted row', async () => {
      const accountId = await seedAccount({ byo: true, quotaLimitOverride: '100' });
      const pinStore = new FakePinStore();
      const bytes = Buffer.alloc(4096, 1);

      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, pinStore.cidFor(bytes), bytes)
      ).rejects.toBeInstanceOf(ConflictException);

      // The adversarial invariant: bytes were NOT pinned to hosted Kubo, and no
      // row (advisory or otherwise) was written to charge or track them.
      expect(pinStore.pinned).toEqual([]);
      expect(await pinsFor(accountId)).toHaveLength(0);
    });

    it('does not promote a pre-existing registry-only row for a BYO account', async () => {
      const accountId = await seedAccount({ byo: true, quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(50, 8);
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      // A size-0 registry membership row already exists (from a prior publish).
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId, cid, size: '0', advisory: true });

      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, cid, bytes)
      ).rejects.toBeInstanceOf(ConflictException);

      // The registry row is untouched (never promoted/charged) and nothing pinned.
      expect(pinStore.pinned).toEqual([]);
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid, size: '0' });
    });
  });

  // A concurrent PATCH /account/byo must serialize against the hosted-ingress
  // BYO read: setByo toggles the flag with a bare UPDATE that takes no advisory
  // lock, so only a users-row lock keeps an upload from reading byo=false, having
  // the toggle commit true under it, and still pinning to hosted Kubo (free
  // hosted storage for a BYO account) — or reading true and 409ing an upload the
  // toggle just made hosted. The read takes the same FOR UPDATE registry.register
  // uses; setByo's UPDATE blocks on it (#716).
  describe('hosted ingress — BYO-flag serialization', () => {
    function buildRegistry(): RegistryService {
      return new RegistryService(
        db.dataSource.getRepository(PinnedCid),
        db.dataSource.getRepository(User),
        db.dataSource,
        new FakePinStore(),
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
      );
    }

    it('a concurrent setByo blocks while an upload holds the users-row lock', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(40, 1);
      const gate = makeGate();
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      // The upload takes the row lock, reads byo=false, then parks — still
      // holding the lock, uncommitted.
      const uploaded = buildService(
        gatedDataSource(db.dataSource, { afterUserRead: gate.onReach }),
        pinStore
      ).upload(accountId, cid, bytes);
      await gate.reached;

      let setByoDone = false;
      const toggled = buildRegistry()
        .setByo(accountId, true)
        .then((r) => {
          setByoDone = true;
          return r;
        });

      // The toggle is blocked on the upload's row lock — it cannot commit.
      await delay(200);
      expect(setByoDone).toBe(false);

      gate.release();
      const result = await uploaded;
      await toggled;
      expect(setByoDone).toBe(true);

      // The upload was hosted at its serialization point, so it pinned and
      // charged; the toggle to BYO applied strictly after it committed.
      expect(result.size).toBe(40);
      expect(pinStore.pinned).toEqual([pinStore.cidFor(bytes)]);
      const user = await db.dataSource.getRepository(User).findOne({ where: { id: accountId } });
      expect(user?.byo).toBe(true);
    });

    it('negative control — without the row lock, the toggle commits mid-upload and a BYO account gets a hosted pin', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(40, 2);
      const gate = makeGate();
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      // The user read drops the FOR UPDATE lock (the pre-fix path); nothing
      // serializes the upload against the toggle.
      const uploaded = buildService(
        gatedDataSource(db.dataSource, { stripUserLock: true, afterUserRead: gate.onReach }),
        pinStore
      ).upload(accountId, cid, bytes);
      await gate.reached; // upload read byo=false with no lock, then paused

      // The toggle commits immediately, mid-upload.
      await buildRegistry().setByo(accountId, true);
      const midUser = await db.dataSource.getRepository(User).findOne({ where: { id: accountId } });
      expect(midUser?.byo).toBe(true);

      gate.release();
      await uploaded;

      // The breach: the account is now BYO, yet the upload pinned to hosted Kubo
      // and wrote an authoritative, quota-charged row — the free hosted storage
      // the row lock closes.
      expect(pinStore.pinned).toEqual([pinStore.cidFor(bytes)]);
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0].advisory).toBe(false);
    });
  });

  describe('atomic byte-pin + register', () => {
    it('pins the bytes and keeps the row on success', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(20, 5);
      const pinStore = new FakePinStore();

      const result = await buildService(db.dataSource, pinStore).upload(
        accountId,
        pinStore.cidFor(bytes),
        bytes
      );

      expect(result.size).toBe(20);
      expect(pinStore.pinned).toEqual([result.cid]);
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0].cid).toBe(result.cid);
    });

    it('rolls back to no durable state when the post-commit pin fails (compensation)', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(20, 6);
      const pinStore = new FakePinStore();
      pinStore.failPin = true;

      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, pinStore.cidFor(bytes), bytes)
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      // Byte-pin + register are all-or-nothing: the row it registered was
      // compensated away, so the account is charged nothing.
      expect(await pinsFor(accountId)).toHaveLength(0);
      expect(await usedBytes(accountId)).toBe(0n);
      // The compensating retire unpinned the CID it could not durably pin.
      expect(pinStore.unpinned).toEqual([pinStore.cidFor(bytes)]);
    });

    // G2: the compensating delete does not take the account lock, so a
    // concurrent same-account upload can transiently count the failed row and
    // 413. That over-restriction is conservative (it never over-admits) and
    // self-heals — once compensation removes the row the account carries no
    // lingering charge, so an at-limit retry fits.
    it('leaves no lingering quota charge after compensation, so a later at-limit upload succeeds', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '20' });

      const failing = new FakePinStore();
      failing.failPin = true;
      const failingBytes = Buffer.alloc(20, 1);
      await expect(
        buildService(db.dataSource, failing).upload(
          accountId,
          failing.cidFor(failingBytes),
          failingBytes
        )
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
      expect(await usedBytes(accountId)).toBe(0n);

      const ok = new FakePinStore();
      const okBytes = Buffer.alloc(20, 2);
      const result = await buildService(db.dataSource, ok).upload(
        accountId,
        ok.cidFor(okBytes),
        okBytes
      );
      expect(result.size).toBe(20);
      expect(await usedBytes(accountId)).toBe(20n);
    });
  });

  describe('post-commit durability — per-CID session lock', () => {
    it('closes the race: while A holds the durability lock through a failing pin, a same-CID B blocks until A compensates, then durably pins itself', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(30, 3);
      const cid = new FakePinStore().cidFor(bytes);

      const pinGate = makeGate();
      const failing = new FakePinStore();
      failing.pinGate = pinGate;
      failing.failPin = true;

      // A: commits its row, then reaches the (failing) pin while still holding
      // the session durability lock.
      const a = buildService(db.dataSource, failing)
        .upload(accountId, cid, bytes)
        .catch((e: unknown) => e);
      await pinGate.reached;

      // B: same CID, its own working pin store — blocks on the durability lock.
      const okStore = new FakePinStore();
      let bResult: UploadResult | undefined;
      const b = buildService(db.dataSource, okStore)
        .upload(accountId, cid, bytes)
        .then((r) => (bResult = r));

      await delay(200);
      expect(bResult).toBeUndefined(); // B is parked on the durability lock

      pinGate.release(); // A's pin fails → A compensates (row deleted, CID unpinned) → releases
      expect(await a).toBeInstanceOf(ServiceUnavailableException);

      await b; // B wakes, finds no row, and pins the bytes itself
      expect(bResult).toMatchObject({ cid, size: 30 });
      expect(okStore.pinned).toEqual([cid]); // B's upload is DURABLE
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0].cid).toBe(cid);
    });

    it('negative control — with the durability lock removed, B returns success for a CID A leaves unpinned', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(30, 4);
      const cid = new FakePinStore().cidFor(bytes);
      const skipDurability = [pinDurabilityLockKey(cid)];

      const pinGate = makeGate();
      const failing = new FakePinStore();
      failing.pinGate = pinGate;
      failing.failPin = true;

      // A skips the durability lock, so it cannot serialize B against A's
      // post-commit pin/compensation window.
      const a = buildService(
        gatedDataSource(db.dataSource, { skipLockKeys: skipDurability }),
        failing
      )
        .upload(accountId, cid, bytes)
        .catch((e: unknown) => e);
      await pinGate.reached; // A committed its row, paused in the failing pin

      // B runs fully while A is parked: it sees A's committed row and returns
      // success WITHOUT pinning (skips its own pin as idempotent).
      const okStore = new FakePinStore();
      const bResult = (await buildService(
        gatedDataSource(db.dataSource, { skipLockKeys: skipDurability }),
        okStore
      ).upload(accountId, cid, bytes)) as UploadResult;
      expect(bResult).toMatchObject({ cid, size: 30 });
      expect(okStore.pinned).toEqual([]); // B pinned nothing — it trusted A's row

      pinGate.release(); // A now fails and compensates the row + unpins the CID
      expect(await a).toBeInstanceOf(ServiceUnavailableException);

      // The breach: B returned success, yet the CID was unpinned and no row
      // survives — a successful upload referencing bytes that are not durable.
      expect(failing.unpinned).toEqual([cid]);
      expect(await pinsFor(accountId)).toHaveLength(0);
    });
  });

  // A register() row records CID membership at size 0 with NO bytes on hosted
  // Kubo. The upload path must NOT trust it as a completed pin (that would leave
  // content unpinned and uncharged); it must promote it — pin + charge — while
  // still no-opping a genuine duplicate of a completed hosted pin.
  describe('registry-only row promotion (durability + quota)', () => {
    function buildRegistry(pinStore: PinStore): RegistryService {
      return new RegistryService(
        db.dataSource.getRepository(PinnedCid),
        db.dataSource.getRepository(User),
        db.dataSource,
        pinStore,
        fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
      );
    }

    it('promotes a size-0 registry-only row: the matching upload pins and charges it, not skip-with-0', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(50, 8);
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      // register(cid): CID membership at size 0, nothing pinned to hosted Kubo.
      await buildRegistry(pinStore).register(accountId, [
        { ipnsName: 'k51-promote-name', contentCids: [cid] },
      ]);
      const registered = (await pinsFor(accountId)).find((row) => row.cid === cid);
      expect(registered).toMatchObject({ size: '0', advisory: false });
      expect(pinStore.pinned).toEqual([]); // register pins nothing

      const result = await buildService(db.dataSource, pinStore).upload(accountId, cid, bytes);

      // The bytes are now DURABLY pinned, the row carries the real size, and the
      // quota is charged — closing the skip-with-size-0 durability/quota hole.
      expect(result).toMatchObject({ cid, size: 50 });
      expect(pinStore.pinned).toEqual([cid]);
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid, size: '50', advisory: false });
      expect(await usedBytes(accountId)).toBe(50n);
    });

    it('no-ops a genuine duplicate of a completed hosted pin — charged once, not re-pinned', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(30, 9);
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      const first = await buildService(db.dataSource, pinStore).upload(accountId, cid, bytes);
      expect(first.size).toBe(30);
      expect(pinStore.pinned).toEqual([first.cid]);

      // The second upload finds a COMPLETED hosted pin (size > 0): idempotent
      // no-op — no second pin, no second charge.
      const second = await buildService(db.dataSource, pinStore).upload(accountId, cid, bytes);
      expect(second).toMatchObject({ cid: first.cid, size: 30 });
      expect(pinStore.pinned).toEqual([first.cid]); // not re-pinned
      expect(await pinsFor(accountId)).toHaveLength(1);
      expect(await usedBytes(accountId)).toBe(30n); // charged once
    });

    it('gates the promotion on the hosted quota: an over-limit promote 413s and leaves the registration at size 0', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '40' });
      const bytes = Buffer.alloc(50, 4);
      const pinStore = new FakePinStore();
      const cid = pinStore.cidFor(bytes);

      await buildRegistry(pinStore).register(accountId, [
        { ipnsName: 'k51-overquota-name', contentCids: [cid] },
      ]);

      await expect(
        buildService(db.dataSource, pinStore).upload(accountId, cid, bytes)
      ).rejects.toBeInstanceOf(PayloadTooLargeException);

      // Refused before any pin; the registry-only row is untouched (still size 0).
      expect(pinStore.pinned).toEqual([]);
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid, size: '0' });
    });

    it('reverts a promoted row to size 0 but keeps the registration when the post-commit pin fails', async () => {
      const accountId = await seedAccount({ quotaLimitOverride: '1000' });
      const bytes = Buffer.alloc(50, 2);
      const registerStore = new FakePinStore();
      const cid = registerStore.cidFor(bytes);

      await buildRegistry(registerStore).register(accountId, [
        { ipnsName: 'k51-revert-name', contentCids: [cid] },
      ]);

      const failing = new FakePinStore();
      failing.failPin = true;
      await expect(
        buildService(db.dataSource, failing).upload(accountId, cid, bytes)
      ).rejects.toBeInstanceOf(ServiceUnavailableException);

      // Compensation reverts the size charge but MUST keep the pre-existing
      // registration — a transient pin failure cannot un-register the client's
      // CID membership. No unpin fires: nothing was ever durably pinned.
      const rows = await pinsFor(accountId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid, size: '0' });
      expect(await usedBytes(accountId)).toBe(0n);
      expect(failing.unpinned).toEqual([]);
    });
  });
});
