import { FakeRepository } from './fake-repo';

/**
 * In-memory stand-in for the sliver of the TypeORM `EntityManager` surface the
 * mailbox service touches inside a transaction: `query` (the advisory-lock
 * acquire, a no-op here) and `getRepository` (routed to the same in-memory
 * `FakeRepository` the test inspects). The fake runs single-threaded, so there
 * is no race to serialize — the advisory lock's job is proven against a real
 * Postgres in `mailbox.concurrency.test.ts`; these fakes only exercise the
 * business logic (cap, TTL purge, idempotent replay) unchanged.
 */
class FakeEntityManager {
  constructor(private readonly repo: FakeRepository<{ id: string }>) {}

  async query(): Promise<unknown[]> {
    return [];
  }

  getRepository(): FakeRepository<{ id: string }> {
    return this.repo;
  }
}

/**
 * In-memory stand-in for the narrow `DataSource.transaction` surface the mailbox
 * service uses. Runs the work function immediately against a manager backed by
 * the supplied repository — no isolation, since the fake has no concurrency to
 * isolate. A thrown work function (e.g. the cap `ConflictException`) propagates
 * unchanged, mirroring a transaction rollback.
 */
export class FakeDataSource {
  private readonly manager: FakeEntityManager;

  constructor(repo: FakeRepository<{ id: string }>) {
    this.manager = new FakeEntityManager(repo);
  }

  async transaction<T>(work: (manager: FakeEntityManager) => Promise<T>): Promise<T> {
    return work(this.manager);
  }
}
