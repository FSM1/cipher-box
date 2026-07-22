import { secp256k1 } from '@noble/curves/secp256k1';
import { UnauthorizedException } from '@nestjs/common';
import { DataSource, FindOperator } from 'typeorm';
import { beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { FakeRepository } from '../../testing/fake-repo';
import { fakeConfig } from '../../testing/fakes';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { RegistryService } from './registry.service';

function newPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
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

/**
 * A DataSource whose transaction runs inline against the in-memory repos and
 * whose query runner no-ops every advisory-lock statement — the post-commit
 * unpin guard's session lock has no effect against a single-threaded fake, so
 * its recount runs directly against the in-memory pins repo. The genuine
 * advisory-lock/lock_timeout/refcount semantics are proven on a real Postgres
 * in registry.service.integration.test.ts; here only the row LOGIC is unit
 * tested.
 */
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

/** Records every physical unpin so the refcount-zero decision is observable. */
class FakePinStore extends PinStore {
  readonly unpinned: string[] = [];
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

const GIB = 1024 * 1024 * 1024;

describe('RegistryService', () => {
  let names: InAwareRepository<NameInventory>;
  let pins: InAwareRepository<PinnedCid>;
  let users: FakeRepository<User>;
  let pinStore: FakePinStore;
  let service: RegistryService;

  function build(config: Record<string, string | undefined> = {}) {
    names = new InAwareRepository<NameInventory>();
    pins = new InAwareRepository<PinnedCid>();
    users = new FakeRepository<User>();
    pinStore = new FakePinStore();
    service = new RegistryService(
      pins as never,
      users as never,
      fakeDataSource([
        [User, users],
        [NameInventory, names],
        [PinnedCid, pins],
      ]),
      pinStore,
      fakeConfig(config).service
    );
  }

  async function account(overrides: Partial<User> = {}): Promise<string> {
    const user = await users.save({ publicKey: newPublicKey(), byo: false, ...overrides } as never);
    return user.id;
  }

  beforeEach(() => build());

  describe('register — register-first, idempotent upserts', () => {
    it('creates the name row before any content pin, and pins head + content', async () => {
      const acct = await account();
      const result = await service.register(acct, [
        { ipnsName: 'k51name', headCid: 'bafyHead', contentCids: ['bafyA', 'bafyB'] },
      ]);

      expect(result).toEqual({ names: 1, cids: 3 });
      // The name is inventoried (register-first) with its head as a routing hint.
      expect(names.rows).toHaveLength(1);
      expect(names.rows[0]).toMatchObject({
        accountId: acct,
        ipnsName: 'k51name',
        headCid: 'bafyHead',
      });
      // Head + content are all pinned under the account.
      expect(pins.rows.map((r) => r.cid).sort()).toEqual(['bafyA', 'bafyB', 'bafyHead']);
      expect(pins.rows.every((r) => r.accountId === acct)).toBe(true);
    });

    it('registers a bare name with no content when headCid and contentCids are absent', async () => {
      const acct = await account();
      const result = await service.register(acct, [{ ipnsName: 'k51bare', contentCids: [] }]);
      expect(result).toEqual({ names: 1, cids: 0 });
      expect(names.rows).toHaveLength(1);
      expect(pins.rows).toHaveLength(0);
    });

    it('reports the DISTINCT name count, not the raw batch length', async () => {
      const acct = await account();
      // The same name appears in two entries; the last-provided head wins.
      const result = await service.register(acct, [
        { ipnsName: 'dup', headCid: 'bafyH1', contentCids: ['bafyA'] },
        { ipnsName: 'dup', headCid: 'bafyH2', contentCids: ['bafyB'] },
      ]);
      expect(result).toEqual({ names: 1, cids: 4 });
      expect(names.rows).toHaveLength(1);
      expect(names.rows[0].headCid).toBe('bafyH2');
    });

    it('is idempotent: replaying the same batch adds no duplicate rows', async () => {
      const acct = await account();
      const batch = [{ ipnsName: 'k51name', headCid: 'bafyHead', contentCids: ['bafyA'] }];
      await service.register(acct, batch);
      await service.register(acct, batch);
      expect(names.rows).toHaveLength(1);
      expect(pins.rows).toHaveLength(2); // bafyHead + bafyA, once each
    });

    it('advances the head on re-publish without duplicating the name row', async () => {
      const acct = await account();
      await service.register(acct, [{ ipnsName: 'k51name', headCid: 'bafyOld', contentCids: [] }]);
      await service.register(acct, [{ ipnsName: 'k51name', headCid: 'bafyNew', contentCids: [] }]);
      expect(names.rows).toHaveLength(1);
      expect(names.rows[0].headCid).toBe('bafyNew');
    });

    it('marks rows advisory for a BYO account', async () => {
      const acct = await account({ byo: true });
      await service.register(acct, [{ ipnsName: 'k51byo', contentCids: ['bafyC'] }]);
      expect(pins.rows[0].advisory).toBe(true);
    });

    it('rejects registration for an unknown account (fail-closed)', async () => {
      await expect(
        service.register('00000000-0000-4000-8000-000000000000', [
          { ipnsName: 'k51x', contentCids: [] },
        ])
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });

  describe('retire — union liveness, refcounted physical unpin', () => {
    it('keeps a CID pinned while another account still holds a row, unpins at global zero', async () => {
      const alice = await account();
      const bob = await account();
      // Both accounts register the same shared content CID.
      await service.register(alice, [{ ipnsName: 'k51a', contentCids: ['bafyShared'] }]);
      await service.register(bob, [{ ipnsName: 'k51b', contentCids: ['bafyShared'] }]);

      // Alice retires her row: the CID survives (Bob still references it).
      const first = await service.retire(alice, ['bafyShared']);
      expect(first).toEqual({ retired: 1, unpinned: 0 });
      expect(pinStore.unpinned).toEqual([]);
      expect(pins.rows.filter((r) => r.cid === 'bafyShared')).toHaveLength(1);

      // Bob retires the last row: global refcount hits zero → physical unpin.
      const second = await service.retire(bob, ['bafyShared']);
      expect(second).toEqual({ retired: 1, unpinned: 1 });
      expect(pinStore.unpinned).toEqual(['bafyShared']);
      expect(pins.rows.filter((r) => r.cid === 'bafyShared')).toHaveLength(0);
    });

    it('retires a name row without any unpin (names never carry bytes)', async () => {
      const acct = await account();
      await service.register(acct, [{ ipnsName: 'k51name', headCid: 'bafyHead', contentCids: [] }]);
      const result = await service.retire(acct, ['k51name']);
      // The name row is gone; the head CID pin is untouched (retire targeted the name only).
      expect(result.retired).toBe(1);
      expect(result.unpinned).toBe(0);
      expect(names.rows).toHaveLength(0);
      expect(pins.rows).toHaveLength(1);
      expect(pinStore.unpinned).toEqual([]);
    });

    it('only the row-holding account can drop the refcount — a foreign retire is a no-op', async () => {
      const owner = await account();
      const stranger = await account();
      await service.register(owner, [{ ipnsName: 'k51o', contentCids: ['bafyOwned'] }]);

      const result = await service.retire(stranger, ['bafyOwned']);
      expect(result).toEqual({ retired: 0, unpinned: 0 });
      expect(pinStore.unpinned).toEqual([]);
      expect(pins.rows.filter((r) => r.cid === 'bafyOwned')).toHaveLength(1);
    });

    it('is idempotent: retiring an already-gone target succeeds as a no-op', async () => {
      const acct = await account();
      const result = await service.retire(acct, ['never-registered']);
      expect(result).toEqual({ retired: 0, unpinned: 0 });
    });

    it('does not surface a 500 when the post-commit unpin throws a non-contention error, still reporting the committed retire', async () => {
      const acct = await account();
      await service.register(acct, [{ ipnsName: 'k51e', contentCids: ['bafyUnpinFails'] }]);

      // The physical unpin is best-effort after the row delete commits, so an
      // arbitrary (non-lock-timeout) failure must be logged and skipped, never
      // rethrown into a 500.
      const throwing = new (class extends FakePinStore {
        override async unpin(): Promise<boolean> {
          throw new Error('kubo unreachable');
        }
      })();
      service = new RegistryService(
        pins as never,
        users as never,
        fakeDataSource([
          [User, users],
          [NameInventory, names],
          [PinnedCid, pins],
        ]),
        throwing,
        fakeConfig({}).service
      );

      const result = await service.retire(acct, ['bafyUnpinFails']);

      expect(result).toEqual({ retired: 1, unpinned: 0 });
      expect(pins.rows.filter((r) => r.cid === 'bafyUnpinFails')).toHaveLength(0);
    });

    it('does not count a CID whose physical unpin the seam reports as a no-op (returns false)', async () => {
      const acct = await account();
      await service.register(acct, [{ ipnsName: 'k51f', contentCids: ['bafyUnpinNoop'] }]);

      // A refcount-zero CID whose unpin is swallowed (Kubo hiccup / unconfigured
      // store) returns false — the row delete still commits, but the count must
      // reflect the seam, not assume a release happened (#729).
      const noopStore = new (class extends FakePinStore {
        override async unpin(): Promise<boolean> {
          return false;
        }
      })();
      service = new RegistryService(
        pins as never,
        users as never,
        fakeDataSource([
          [User, users],
          [NameInventory, names],
          [PinnedCid, pins],
        ]),
        noopStore,
        fakeConfig({}).service
      );

      const result = await service.retire(acct, ['bafyUnpinNoop']);

      expect(result).toEqual({ retired: 1, unpinned: 0 });
      expect(pins.rows.filter((r) => r.cid === 'bafyUnpinNoop')).toHaveLength(0);
    });
  });

  describe('quota — arithmetic, override, hosted vs BYO advisory', () => {
    async function seedPin(accountId: string, cid: string, size: number): Promise<void> {
      await pins.save({ accountId, cid, size: String(size), advisory: false } as never);
    }

    it('sums the account own pin-row sizes and reports the env-default limit', async () => {
      build({ QUOTA_DEFAULT_BYTES: String(2 * GIB) });
      const acct = await account();
      await seedPin(acct, 'bafy1', 100);
      await seedPin(acct, 'bafy2', 250);

      const quota = await service.quota(acct);
      expect(quota).toEqual({ usedBytes: 350, limitBytes: 2 * GIB, advisory: false });
    });

    it('counts only the account own rows, never another account bytes', async () => {
      const mine = await account();
      const theirs = await account();
      await seedPin(mine, 'bafyMine', 400);
      await seedPin(theirs, 'bafyTheirs', 999);

      const quota = await service.quota(mine);
      expect(quota.usedBytes).toBe(400);
    });

    it('honors the per-account override over the env default', async () => {
      build({ QUOTA_DEFAULT_BYTES: String(2 * GIB) });
      const acct = await account({ quotaLimitOverride: String(5000) });
      await seedPin(acct, 'bafy1', 100);

      const quota = await service.quota(acct);
      expect(quota.limitBytes).toBe(5000);
      expect(quota.usedBytes).toBe(100);
    });

    it('falls back to the 10 GiB default when QUOTA_DEFAULT_BYTES is garbage', async () => {
      build({ QUOTA_DEFAULT_BYTES: 'not-a-number' });
      const acct = await account();
      const quota = await service.quota(acct);
      expect(quota.limitBytes).toBe(10 * GIB);
    });

    it('reports advisory:true for a BYO account, still summing its rows', async () => {
      const acct = await account({ byo: true });
      await seedPin(acct, 'bafyByo', 777);
      const quota = await service.quota(acct);
      expect(quota.advisory).toBe(true);
      expect(quota.usedBytes).toBe(777);
    });

    it('rejects a quota query for an unknown account', async () => {
      await expect(service.quota('00000000-0000-4000-8000-000000000000')).rejects.toBeInstanceOf(
        UnauthorizedException
      );
    });
  });

  describe('setByo', () => {
    it('flips the account BYO flag', async () => {
      const acct = await account({ byo: false });
      const result = await service.setByo(acct, true);
      expect(result).toEqual({ byo: true });
      expect(users.rows[0].byo).toBe(true);
    });

    it('rejects a BYO toggle for an unknown account', async () => {
      await expect(
        service.setByo('00000000-0000-4000-8000-000000000000', true)
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });
  });
});
