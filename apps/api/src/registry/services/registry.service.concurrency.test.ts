import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { DataSource, EntityManager, FindOneOptions, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { AuthMethod } from '../../auth/entities/auth-method.entity';
import { RefreshToken } from '../../auth/entities/refresh-token.entity';
import { User } from '../../auth/entities/user.entity';
import { fakeConfig } from '../../testing/fakes';
import { NameInventory } from '../entities/name-inventory.entity';
import { PinnedCid } from '../entities/pinned-cid.entity';
import { PinStore } from '../pin-store';
import { RegistryService } from './registry.service';

/**
 * The BYO-flag read serialized against a concurrent toggle, proven on a REAL
 * Postgres. register reads `users.byo` under a `pessimistic_write` row lock
 * inside its transaction; a concurrent setByo (a plain row UPDATE) must block
 * on that lock until register commits, so a new pin row can never be stamped
 * with a BYO flag that changed mid-transaction. Real row locks are genuine
 * Postgres behavior — no in-memory fake can exercise the block — so this suite
 * is opt-in: it runs only when `REGISTRY_DB_TEST=1` with a reachable Postgres
 * (standard DB_* env, defaults matching docker/docker-compose.yml). Left unset
 * — as in the fake-only `Run API unit suite` CI job — the whole suite skips.
 */
const RUN_DB_TEST = process.env.REGISTRY_DB_TEST === '1';

const DB = {
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  user: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
};

// A throwaway database, created and dropped by this suite, so the shared dev
// `cipherbox` database is never touched.
const TEST_DB = 'cipherbox_registry_byo_test';

/** Run one-off admin DDL (CREATE/DROP DATABASE) via a short-lived connection to
 * the default `postgres` database. Kept off TypeORM's entity path so it needs no
 * `pg` type declarations. */
async function adminExec(sql: string): Promise<void> {
  const admin = new DataSource({
    type: 'postgres',
    host: DB.host,
    port: DB.port,
    username: DB.user,
    password: DB.password,
    database: 'postgres',
  });
  await admin.initialize();
  try {
    await admin.query(sql);
  } finally {
    await admin.destroy();
  }
}

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

class NoopPinStore extends PinStore {
  async unpin(): Promise<void> {}
}

/** A barrier register trips the instant it has read (and locked) the users row. */
interface ReadGate {
  reached: Promise<void>;
  release: () => void;
  onRead: () => Promise<void>;
}

function makeGate(): ReadGate {
  let signalReached!: () => void;
  let release!: () => void;
  const reached = new Promise<void>((resolve) => (signalReached = resolve));
  const open = new Promise<void>((resolve) => (release = resolve));
  return {
    reached,
    release,
    onRead: async () => {
      signalReached();
      await open;
    },
  };
}

/**
 * A DataSource that runs the real transaction but pauses register the instant
 * its `User.findOne` returns — while the row lock is still held — so a racing
 * setByo can be observed to block. `stripLock` drops the pessimistic lock to
 * model the pre-fix read and reproduce the race.
 */
function gatedDataSource(
  real: DataSource,
  onRead: () => Promise<void>,
  stripLock = false
): DataSource {
  const wrapUserRepo = (repo: Repository<User>): Repository<User> =>
    new Proxy(repo, {
      get(target, prop, receiver) {
        if (prop === 'findOne') {
          return async (options: FindOneOptions<User>) => {
            const opts = stripLock ? { ...options, lock: undefined } : options;
            const row = await target.findOne(opts);
            await onRead();
            return row;
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
            if (prop === 'getRepository') {
              return (entity: unknown) => {
                const repo = target.getRepository(entity as never);
                return entity === User ? wrapUserRepo(repo as Repository<User>) : repo;
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

describe.skipIf(!RUN_DB_TEST)('RegistryService BYO-flag serialization (real Postgres)', () => {
  let dataSource: DataSource;

  beforeAll(async () => {
    await adminExec(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
    await adminExec(`CREATE DATABASE ${TEST_DB}`);

    dataSource = new DataSource({
      type: 'postgres',
      host: DB.host,
      port: DB.port,
      username: DB.user,
      password: DB.password,
      database: TEST_DB,
      entities: [User, AuthMethod, RefreshToken, NameInventory, PinnedCid],
      synchronize: false,
      uuidExtension: 'pgcrypto',
      // Room for register's held transaction plus the racing setByo connection.
      extra: { max: 10 },
    });
    await dataSource.initialize();
    await dataSource.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    await dataSource.synchronize();
  }, 30_000);

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await adminExec(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
  });

  beforeEach(async () => {
    await dataSource.query('TRUNCATE TABLE users CASCADE');
  });

  // register takes the gated DataSource; setByo takes the real one (a plain
  // row UPDATE). Both share the same underlying users table and connection pool.
  function buildService(ds: DataSource): RegistryService {
    return new RegistryService(
      dataSource.getRepository(PinnedCid) as never,
      dataSource.getRepository(User) as never,
      ds as never,
      new NoopPinStore(),
      fakeConfig({}).service
    );
  }

  async function seedAccount(byo: boolean): Promise<string> {
    const user = await dataSource
      .getRepository(User)
      .save({ publicKey: compressedPublicKey(), byo });
    return user.id;
  }

  async function pinsFor(accountId: string): Promise<PinnedCid[]> {
    return dataSource.getRepository(PinnedCid).find({ where: { accountId } });
  }

  it('a concurrent setByo blocks while register holds the users-row lock; the new pin row keeps the value read under the lock', async () => {
    const accountId = await seedAccount(false);
    const gate = makeGate();
    const register = buildService(gatedDataSource(dataSource, gate.onRead));

    const registered = register.register(accountId, [
      { ipnsName: token(), contentCids: [token()] },
    ]);

    // register has taken the row lock and read byo=false; it now waits, still
    // holding the lock and uncommitted.
    await gate.reached;

    let setByoDone = false;
    const toggled = buildService(dataSource)
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
    const user = await dataSource.getRepository(User).findOne({ where: { id: accountId } });
    expect(user?.byo).toBe(true);
  });

  it('negative control — without the row lock, setByo commits between the read and the insert, tearing the advisory stamp', async () => {
    const accountId = await seedAccount(false);
    const gate = makeGate();
    // Same interleaving, but the users read drops the pessimistic lock (the
    // pre-fix code path) — nothing serializes register against the toggle.
    const register = buildService(gatedDataSource(dataSource, gate.onRead, true));

    const registered = register.register(accountId, [
      { ipnsName: token(), contentCids: [token()] },
    ]);
    await gate.reached;

    // With no row lock, the toggle commits immediately, mid-register.
    await buildService(dataSource).setByo(accountId, true);
    const midUser = await dataSource.getRepository(User).findOne({ where: { id: accountId } });
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
