import { FakeRepository } from './fake-repo';

type AnyRepo = FakeRepository<{ id: string }>;

/**
 * In-memory stand-in for the sliver of the TypeORM `EntityManager` surface a
 * service touches inside a transaction: `query` (the advisory-lock acquire, a
 * no-op here) and `getRepository` (routed to the in-memory `FakeRepository` the
 * test inspects). An entity→repo map routes secondary entities (e.g. the mailbox
 * service reads `User` under its lock); anything unmapped falls back to the
 * primary repo. The fake runs single-threaded, so there is no race to serialize
 * — the advisory lock's job is proven against a real Postgres in the
 * integration suite; these fakes only exercise the business logic unchanged.
 */
class FakeEntityManager {
  constructor(
    private readonly fallback: AnyRepo,
    private readonly repos: Map<unknown, AnyRepo>
  ) {}

  async query(): Promise<unknown[]> {
    return [];
  }

  getRepository(entity?: unknown): AnyRepo {
    return this.repos.get(entity) ?? this.fallback;
  }
}

/**
 * In-memory stand-in for the narrow `DataSource.transaction` surface a service
 * uses. Runs the work function immediately against a manager backed by the
 * supplied repositories — no isolation, since the fake has no concurrency to
 * isolate. A thrown work function (e.g. the cap `ConflictException`) propagates
 * unchanged, mirroring a transaction rollback.
 */
export class FakeDataSource {
  private readonly manager: FakeEntityManager;

  constructor(repo: AnyRepo, repos: Array<[unknown, AnyRepo]> = []) {
    this.manager = new FakeEntityManager(repo, new Map(repos));
  }

  async transaction<T>(work: (manager: FakeEntityManager) => Promise<T>): Promise<T> {
    return work(this.manager);
  }
}
