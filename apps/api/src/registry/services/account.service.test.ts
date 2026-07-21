import { ServiceUnavailableException } from '@nestjs/common';
import { DataSource, FindOperator, QueryFailedError } from 'typeorm';
import { beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { MailboxMessage } from '../../mailbox/entities/mailbox-message.entity';
import { FakeRepository } from '../../testing/fake-repo';
import { fakeConfig } from '../../testing/fakes';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { AccountService } from './account.service';

/**
 * Records physical unpins so the refcount-zero decision is observable. A CID in
 * `failFor` models a swallowed Kubo failure: `unpin` returns false and records
 * nothing, so the caller's unpin count must exclude it.
 */
class RecordingPinStore extends PinStore {
  readonly unpinned: string[] = [];
  readonly failFor = new Set<string>();
  async unpin(cid: string): Promise<boolean> {
    if (this.failFor.has(cid)) {
      return false;
    }
    this.unpinned.push(cid);
    return true;
  }
}

/** FakeRepository plus the `In([...])` find the survivor check uses. */
class InAwareRepository<T extends { id: string }> extends FakeRepository<T> {
  override async find(options: { where?: Record<string, unknown> } = {}): Promise<T[]> {
    const where = options.where;
    if (!where) {
      return [...this.rows];
    }
    return this.rows.filter((row) =>
      Object.entries(where).every(([key, expected]) => {
        if (expected instanceof FindOperator && expected.type === 'in') {
          return (expected.value as unknown[]).includes((row as Record<string, unknown>)[key]);
        }
        return (row as Record<string, unknown>)[key] === expected;
      })
    );
  }
}

interface Repos {
  users: FakeRepository<User>;
  pins: InAwareRepository<PinnedCid>;
  names: InAwareRepository<NameInventory>;
  mailbox: InAwareRepository<MailboxMessage>;
}

/**
 * A DataSource whose transaction runs inline against the in-memory repos. The
 * advisory-lock / lock_timeout queries no-op unless `failLockCode` is set, which
 * makes the advisory acquire raise a Postgres error (drives the 503 mapping).
 */
function fakeDataSource(repos: Repos, failLockCode?: string): DataSource {
  const byEntity = new Map<unknown, unknown>([
    [User, repos.users],
    [PinnedCid, repos.pins],
    [NameInventory, repos.names],
    [MailboxMessage, repos.mailbox],
  ]);
  return {
    transaction: (runInTransaction: (manager: unknown) => unknown) =>
      Promise.resolve().then(() =>
        runInTransaction({
          getRepository: (entity: unknown) => byEntity.get(entity),
          query: async (sql: string) => {
            if (failLockCode && /pg_advisory_xact_lock/i.test(sql)) {
              throw new QueryFailedError(sql, [], { code: failLockCode } as unknown as Error);
            }
            return [];
          },
        })
      ),
  } as unknown as DataSource;
}

describe('AccountService.deleteAccount', () => {
  let repos: Repos;
  let pinStore: RecordingPinStore;

  beforeEach(() => {
    repos = {
      users: new FakeRepository<User>(),
      pins: new InAwareRepository<PinnedCid>(),
      names: new InAwareRepository<NameInventory>(),
      mailbox: new InAwareRepository<MailboxMessage>(),
    };
    pinStore = new RecordingPinStore();
  });

  function build(failLockCode?: string): AccountService {
    return new AccountService(
      repos.users as never,
      repos.pins as never,
      fakeDataSource(repos, failLockCode) as never,
      pinStore,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
    );
  }

  async function seedAccount(publicKey = 'pk-owner'): Promise<string> {
    const user = await repos.users.save({ publicKey, byo: false } as never);
    return user.id;
  }

  it('hard-deletes every row for the account and unpins its sole-held CIDs', async () => {
    const accountId = await seedAccount('pk-owner');
    await repos.names.save({ accountId, ipnsName: 'k51name', headCid: null } as never);
    await repos.pins.save({ accountId, cid: 'cidSole', size: '10', advisory: false } as never);
    await repos.mailbox.save({
      recipientPublicKey: 'pk-owner',
      idempotencyScope: 's',
      blob: Buffer.from('x'),
      receivedAt: new Date(),
    } as never);
    // A row for a different account must be untouched.
    const other = await seedAccount('pk-other');
    await repos.pins.save({
      accountId: other,
      cid: 'cidOther',
      size: '1',
      advisory: false,
    } as never);

    const result = await build().deleteAccount(accountId);

    expect(result).toEqual({ namesRetired: 1, pinsRetired: 1, mailboxPurged: 1, unpinned: 1 });
    expect(pinStore.unpinned).toEqual(['cidSole']);
    expect(repos.users.rows.map((r) => r.id)).toEqual([other]);
    expect(repos.pins.rows.map((r) => r.cid)).toEqual(['cidOther']);
    expect(repos.names.rows).toHaveLength(0);
    expect(repos.mailbox.rows).toHaveLength(0);
  });

  it('does NOT unpin a co-registered CID another account still holds (union liveness)', async () => {
    const a = await seedAccount('pk-a');
    const b = await seedAccount('pk-b');
    await repos.pins.save({ accountId: a, cid: 'shared', size: '5', advisory: false } as never);
    await repos.pins.save({ accountId: b, cid: 'shared', size: '5', advisory: false } as never);

    const result = await build().deleteAccount(a);

    expect(result.pinsRetired).toBe(1);
    expect(result.unpinned).toBe(0);
    expect(pinStore.unpinned).toEqual([]);
    expect(repos.pins.rows.map((r) => r.accountId)).toEqual([b]);
  });

  it('counts only physically-unpinned CIDs, not the refcount-zero selection', async () => {
    const a = await seedAccount('pk-a');
    for (const cid of ['ok1', 'fail', 'ok2']) {
      await repos.pins.save({ accountId: a, cid, size: '1', advisory: false } as never);
    }
    // The middle CID's physical unpin is swallowed (Kubo failure) — it is still
    // at refcount zero and selected, but must not be reported as released.
    pinStore.failFor.add('fail');

    const result = await build().deleteAccount(a);

    expect(result.pinsRetired).toBe(3);
    expect(result.unpinned).toBe(2);
    expect(pinStore.unpinned).toEqual(['ok1', 'ok2']);
  });

  it('is idempotent for an unknown account: empty result, no unpin, no writes', async () => {
    const result = await build().deleteAccount('00000000-0000-0000-0000-000000000000');
    expect(result).toEqual({ namesRetired: 0, pinsRetired: 0, mailboxPurged: 0, unpinned: 0 });
    expect(pinStore.unpinned).toEqual([]);
  });

  it('maps a lock_timeout abort (55P03) on the advisory acquire to a retryable 503', async () => {
    const accountId = await seedAccount();
    await expect(build('55P03').deleteAccount(accountId)).rejects.toBeInstanceOf(
      ServiceUnavailableException
    );
  });
});
