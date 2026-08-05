import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { MailboxMessage } from '../entities/mailbox-message.entity';
import { MailboxService, SWEEP_MAX_BATCHES } from './mailbox.service';

/**
 * The global dormant-mailbox TTL sweep proven against a REAL Postgres.
 *
 * The lazy per-recipient purge only fires on a recipient's own post/poll, so the
 * cases that matter here — a dormant mailbox that never polls, and a concurrent
 * post that must survive a sweep in flight — are genuine Postgres timing/DELETE
 * semantics no in-memory fake reproduces.
 */

const TTL_MS = 90 * 24 * 60 * 60 * 1000;

function compressedPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

function base64Blob(bytes: number): string {
  return Buffer.alloc(bytes, 7).toString('base64');
}

describe('MailboxService global TTL sweep (real Postgres)', () => {
  let db: IntegrationDatabase;
  let repo: Repository<MailboxMessage>;
  const clock = new FakeClock();

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 30 });
    repo = db.dataSource.getRepository(MailboxMessage);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE mailbox_messages');
  });

  function buildService(env: Record<string, string | undefined> = {}): {
    service: MailboxService;
    users: FakeRepository<User>;
  } {
    const users = new FakeRepository<User>();
    const service = new MailboxService(
      repo,
      users as never,
      db.dataSource,
      new IdentityService(),
      clock,
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '0', ...env }).service
    );
    return { service, users };
  }

  /** Seed one row with an explicit age, bypassing the service so no purge fires. */
  async function seedRow(recipient: string, ageMs: number): Promise<string> {
    const saved = await repo.save({
      recipientPublicKey: recipient,
      idempotencyScope: randomBytes(32).toString('hex'),
      blob: Buffer.alloc(16, 1),
      receivedAt: new Date(clock.now().getTime() - ageMs),
    });
    return saved.id;
  }

  /** Bulk-seed `count` already-expired rows for a recipient in one INSERT. */
  async function seedExpiredBatch(recipient: string, count: number): Promise<void> {
    const receivedAt = new Date(clock.now().getTime() - (TTL_MS + 60_000));
    await db.dataSource.query(
      `INSERT INTO mailbox_messages (recipient_public_key, idempotency_scope, blob, received_at)
       SELECT $1, lpad(g::text, 64, '0'), '\\x01'::bytea, $2::timestamptz
       FROM generate_series(1, $3) AS g`,
      [recipient, receivedAt.toISOString(), count]
    );
  }

  it('deletes rows older than 90 days and keeps fresh ones, with no recipient activity', async () => {
    const dormant = compressedPublicKey();
    const active = compressedPublicKey();
    const { service } = buildService();

    const expiredA = await seedRow(dormant, TTL_MS + 60_000);
    const expiredB = await seedRow(dormant, TTL_MS + 24 * 60 * 60 * 1000);
    const freshDormant = await seedRow(dormant, TTL_MS - 60_000);
    const freshActive = await seedRow(active, 1000);

    const deleted = await service.sweepExpired();

    expect(deleted).toBe(2);
    const survivors = (await repo.find()).map((r) => r.id).sort();
    expect(survivors).toEqual([freshDormant, freshActive].sort());
    expect(survivors).not.toContain(expiredA);
    expect(survivors).not.toContain(expiredB);
  });

  it('is exactly at the cutoff boundary: strictly-older is deleted, exactly-90d survives', async () => {
    const recipient = compressedPublicKey();
    const { service } = buildService();

    // received_at < now - TTL deletes; == cutoff is NOT strictly less, so survives.
    const justExpired = await seedRow(recipient, TTL_MS + 1);
    const exactlyAtCutoff = await seedRow(recipient, TTL_MS);

    const deleted = await service.sweepExpired();

    expect(deleted).toBe(1);
    const survivors = (await repo.find()).map((r) => r.id);
    expect(survivors).toEqual([exactlyAtCutoff]);
    expect(survivors).not.toContain(justExpired);
  });

  it('batches: drains a backlog larger than one batch across looped deletes', async () => {
    const recipient = compressedPublicKey();
    const { service } = buildService({ MAILBOX_SWEEP_BATCH_SIZE: '50' });

    const EXPIRED = 220;
    for (let i = 0; i < EXPIRED; i += 1) {
      await seedRow(recipient, TTL_MS + 60_000 + i);
    }
    const fresh = await seedRow(recipient, 1000);

    const deleted = await service.sweepExpired();

    expect(deleted).toBe(EXPIRED);
    const survivors = (await repo.find()).map((r) => r.id);
    expect(survivors).toEqual([fresh]);
  });

  it('respects the internal SWEEP_MAX_BATCHES cap, leaving the remainder for the next run', async () => {
    const recipient = compressedPublicKey();
    // batchSize=1 means each batch deletes one row and never short-circuits on
    // drain, so a run is bounded solely by the SWEEP_MAX_BATCHES const. Seed a
    // few rows past the cap: the first run stops at the cap, the next drains.
    const REMAINDER = 3;
    const { service } = buildService({ MAILBOX_SWEEP_BATCH_SIZE: '1' });

    await seedExpiredBatch(recipient, SWEEP_MAX_BATCHES + REMAINDER);

    const firstRun = await service.sweepExpired();
    expect(firstRun).toBe(SWEEP_MAX_BATCHES);
    expect(await repo.count()).toBe(REMAINDER);

    const secondRun = await service.sweepExpired();
    expect(secondRun).toBe(REMAINDER);
    expect(await repo.count()).toBe(0);
  });

  it('adversarial: a post concurrent with a sweep survives while dormant expired rows are deleted', async () => {
    const dormant = compressedPublicKey();
    const recipient = compressedPublicKey();
    const sender = compressedPublicKey();
    const { service, users } = buildService({ MAILBOX_SWEEP_BATCH_SIZE: '10' });
    void users.save({ publicKey: recipient } as never);

    // A large dormant backlog so the sweep loops across many awaits, giving the
    // concurrent post real opportunity to interleave mid-sweep.
    const EXPIRED = 300;
    for (let i = 0; i < EXPIRED; i += 1) {
      await seedRow(dormant, TTL_MS + 60_000 + i);
    }

    const [deleted, posted] = await Promise.all([
      service.sweepExpired(),
      service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'concurrent-post',
      }),
    ]);

    // The fresh post — received_at = clock.now(), never < cutoff — must survive
    // the sweep untouched, and every expired dormant row must be gone.
    expect(deleted).toBe(EXPIRED);
    const survivors = await repo.find();
    expect(survivors).toHaveLength(1);
    expect(survivors[0].id).toBe(posted.id);
    expect(survivors[0].recipientPublicKey).toBe(recipient);
  });
});
