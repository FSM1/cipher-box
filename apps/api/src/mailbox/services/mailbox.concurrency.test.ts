import { ConflictException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { DataSource, Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { MailboxMessage } from '../entities/mailbox-message.entity';
import { MailboxService } from './mailbox.service';

/**
 * The pending-cap serialization guard proven against a REAL Postgres.
 *
 * The fix wraps purge → count → cap-check → insert in one transaction under a
 * per-recipient `pg_advisory_xact_lock`. Advisory locks and the count→insert
 * isolation they provide are genuine Postgres behavior — no sqlite or in-memory
 * fake can exercise them — so this suite is opt-in: it runs only when
 * `MAILBOX_DB_TEST=1` and a reachable Postgres is configured via the standard
 * DB_* env (defaults match docker/docker-compose.yml). Left unset — as in the
 * fake-only `Run API unit suite` CI job — the whole suite is skipped, never
 * failing for want of a database.
 */
const RUN_DB_TEST = process.env.MAILBOX_DB_TEST === '1';

const DB = {
  host: process.env.DB_HOST ?? 'localhost',
  port: Number(process.env.DB_PORT ?? 5432),
  user: process.env.DB_USERNAME ?? 'postgres',
  password: process.env.DB_PASSWORD ?? 'postgres',
};

// A throwaway database, created and dropped by this suite, so the shared dev
// `cipherbox` database is never touched.
const TEST_DB = 'cipherbox_mailbox_cap_test';

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
  return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
}

function base64Blob(bytes: number): string {
  return Buffer.alloc(bytes, 7).toString('base64');
}

describe.skipIf(!RUN_DB_TEST)('MailboxService pending-cap concurrency (real Postgres)', () => {
  let dataSource: DataSource;
  let repo: Repository<MailboxMessage>;

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
      entities: [MailboxMessage],
      synchronize: false,
      uuidExtension: 'pgcrypto',
      // A pool comfortably wider than any batch below, so the racing posts hold
      // real connections at once and genuinely contend on the advisory lock
      // rather than queueing at the JS pool.
      extra: { max: 30 },
    });
    await dataSource.initialize();
    await dataSource.query('CREATE EXTENSION IF NOT EXISTS pgcrypto');
    await dataSource.synchronize();
    repo = dataSource.getRepository(MailboxMessage);
  }, 30_000);

  afterAll(async () => {
    if (dataSource?.isInitialized) {
      await dataSource.destroy();
    }
    await adminExec(`DROP DATABASE IF EXISTS ${TEST_DB} WITH (FORCE)`);
  });

  beforeEach(async () => {
    await dataSource.query('TRUNCATE TABLE mailbox_messages');
  });

  function buildService(cap: number): {
    service: MailboxService;
    recipient: string;
    sender: string;
  } {
    const clock = new FakeClock();
    const users = new FakeRepository<User>();
    const recipient = compressedPublicKey();
    const sender = compressedPublicKey();
    // Recipient existence is checked outside the serialized window, so a fake
    // user repo (seeded with the recipient) is faithful; the mailbox reads and
    // writes go to the real Postgres via the real repo + DataSource.
    void users.save({ publicKey: recipient } as never);
    const service = new MailboxService(
      repo,
      users as never,
      dataSource,
      new IdentityService(),
      clock,
      fakeConfig({ MAILBOX_PENDING_CAP: String(cap) }).service
    );
    return { service, recipient, sender };
  }

  async function seedPending(recipient: string, count: number): Promise<void> {
    const now = new Date();
    const rows = Array.from({ length: count }, () => ({
      recipientPublicKey: recipient,
      idempotencyScope: randomBytes(32).toString('hex'),
      blob: Buffer.alloc(16, 1),
      receivedAt: now,
    }));
    await repo.save(rows);
  }

  it('at cap - 1, only ONE of N concurrent distinct-key posts wins; the rest 409, and the cap is never exceeded', async () => {
    const CAP = 100;
    const RACERS = 8;
    const { service, recipient, sender } = buildService(CAP);
    await seedPending(recipient, CAP - 1);

    const outcomes = await Promise.allSettled(
      Array.from({ length: RACERS }, (_, i) =>
        service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: `race-${i}`,
        })
      )
    );

    const fulfilled = outcomes.filter((o) => o.status === 'fulfilled');
    const conflicts = outcomes.filter(
      (o): o is PromiseRejectedResult =>
        o.status === 'rejected' && o.reason instanceof ConflictException
    );
    const otherErrors = outcomes.filter(
      (o) => o.status === 'rejected' && !(o.reason instanceof ConflictException)
    );

    // Exactly one racer fills the last slot; every other loses with a 409 and
    // nothing else fails. Without the lock, two+ readers see `cap - 1` and both
    // insert.
    expect(otherErrors).toHaveLength(0);
    expect(fulfilled).toHaveLength(1);
    expect(conflicts).toHaveLength(RACERS - 1);

    const finalCount = await repo.count({ where: { recipientPublicKey: recipient } });
    expect(finalCount).toBe(CAP);
    expect(finalCount).toBeLessThanOrEqual(CAP);
  });

  it('under full saturation, exactly CAP of CAP+extra concurrent posts commit; the surplus 409', async () => {
    const CAP = 10;
    const EXTRA = 8;
    const { service, recipient, sender } = buildService(CAP);

    const outcomes = await Promise.allSettled(
      Array.from({ length: CAP + EXTRA }, (_, i) =>
        service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: `sat-${i}`,
        })
      )
    );

    const fulfilled = outcomes.filter((o) => o.status === 'fulfilled');
    const conflicts = outcomes.filter(
      (o): o is PromiseRejectedResult =>
        o.status === 'rejected' && o.reason instanceof ConflictException
    );

    expect(fulfilled).toHaveLength(CAP);
    expect(conflicts).toHaveLength(EXTRA);

    const finalCount = await repo.count({ where: { recipientPublicKey: recipient } });
    expect(finalCount).toBe(CAP);
    expect(finalCount).toBeLessThanOrEqual(CAP);
  });
});
