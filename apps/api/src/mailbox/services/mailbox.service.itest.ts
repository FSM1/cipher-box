import { ConflictException, ServiceUnavailableException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomBytes } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../../auth/entities/user.entity';
import { IdentityService } from '../../auth/services/identity.service';
import { MetricsService } from '../../ops/metrics.service';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../../testing/integration-db';
import { MailboxMessage } from '../entities/mailbox-message.entity';
import { MailboxService } from './mailbox.service';

/**
 * The pending-cap serialization guard proven against a REAL Postgres.
 *
 * The fix wraps purge → count → cap-check → insert in one transaction under a
 * per-recipient `pg_advisory_xact_lock`. Advisory locks and the count→insert
 * isolation they provide are genuine Postgres behavior — no in-memory fake can
 * exercise them — so this test lives in the real-Postgres integration suite.
 */

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

describe('MailboxService pending-cap concurrency (real Postgres)', () => {
  let db: IntegrationDatabase;
  let repo: Repository<MailboxMessage>;

  beforeAll(async () => {
    // A pool comfortably wider than any batch below, so racing posts hold real
    // connections at once and genuinely contend on the advisory lock rather than
    // queueing at the JS pool.
    db = await createIntegrationDatabase({ poolMax: 30 });
    repo = db.dataSource.getRepository(MailboxMessage);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE mailbox_messages');
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
      db.dataSource,
      new IdentityService(),
      clock,
      new MetricsService(),
      // Disable the advisory-lock wait bound so a slow CI waiter can't 503 before
      // the cap check; the timeout has its own dedicated regression test.
      fakeConfig({ MAILBOX_PENDING_CAP: String(cap), DB_ADVISORY_LOCK_TIMEOUT_MS: '0' }).service
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

  it('a row-lock wait past lock_timeout inside the cap window surfaces a retryable 503, not a 500', async () => {
    const clock = new FakeClock();
    const users = new FakeRepository<User>();
    const recipient = compressedPublicKey();
    const sender = compressedPublicKey();
    void users.save({ publicKey: recipient } as never);
    const service = new MailboxService(
      repo,
      users as never,
      db.dataSource,
      new IdentityService(),
      clock,
      new MetricsService(),
      fakeConfig({ DB_ADVISORY_LOCK_TIMEOUT_MS: '200' }).service
    );

    // An expired row (past the 90-day TTL relative to the FakeClock) that the
    // cap window's purge DELETE must touch.
    const expired = await repo.save({
      recipientPublicKey: recipient,
      idempotencyScope: randomBytes(32).toString('hex'),
      blob: Buffer.alloc(16, 1),
      receivedAt: new Date('2025-09-01T00:00:00Z'),
    });

    // Hold that row locked elsewhere: the advisory acquire succeeds (no
    // contention on the recipient key), then the purge DELETE waits past the
    // transaction-scoped lock_timeout and aborts with 55P03 — which must map
    // to the retryable 503, not escape post()'s dedup catch as a 500.
    const holder = db.dataSource.createQueryRunner();
    await holder.connect();
    await holder.startTransaction();
    await holder.query('SELECT id FROM mailbox_messages WHERE id = $1 FOR UPDATE', [expired.id]);

    try {
      await expect(
        service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: 'row-lock-timeout',
        })
      ).rejects.toBeInstanceOf(ServiceUnavailableException);
    } finally {
      await holder.rollbackTransaction();
      await holder.release();
    }
  });
});
