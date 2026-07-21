import { ServiceUnavailableException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { createHash } from 'node:crypto';
import { Repository } from 'typeorm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { IdentityService } from '../auth/services/identity.service';
import { MailboxMessage } from '../mailbox/entities/mailbox-message.entity';
import { MailboxService } from '../mailbox/services/mailbox.service';
import { FakeRepository } from '../testing/fake-repo';
import { FakeClock, fakeConfig } from '../testing/fakes';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';

/**
 * The advisory-lock `lock_timeout` DoS guard proven against a REAL Postgres.
 *
 * `pg_advisory_xact_lock` holds its pooled connection while WAITING, so under
 * sustained same-key contention an unbounded wait fills the pool with blocked
 * waiters and starves unrelated queries — a service-wide DoS. The fix bounds the
 * wait with `SET LOCAL lock_timeout`; a timed-out waiter aborts, releases its
 * connection, and surfaces a retryable 503. This test saturates one recipient's
 * lock past the pool size and asserts (a) an unrelated query still obtains a
 * connection and (b) the waiters return 503 — and that with the bound removed
 * (the negative control) the pool starves instead.
 */

const RACERS = 6;
const POOL_MAX = 4;

const delay = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

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

/** The service's per-recipient lock key: sha256 of the normalized key, first 8 bytes. */
function recipientLockKey(recipient: string): bigint {
  return createHash('sha256').update(recipient).digest().readBigInt64BE(0);
}

async function settledWithin(p: Promise<unknown>, ms: number): Promise<'settled' | 'pending'> {
  return Promise.race([
    p.then(
      () => 'settled' as const,
      () => 'settled' as const
    ),
    delay(ms).then(() => 'pending' as const),
  ]);
}

describe('Advisory-lock lock_timeout DoS guard (real Postgres)', () => {
  let db: IntegrationDatabase;
  let repo: Repository<MailboxMessage>;

  beforeAll(async () => {
    // A deliberately small pool so saturating one recipient's waiters is cheap.
    db = await createIntegrationDatabase({ poolMax: POOL_MAX });
    repo = db.dataSource.getRepository(MailboxMessage);
  });

  afterAll(async () => {
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE mailbox_messages');
  });

  function buildService(lockTimeoutMs: number): {
    service: MailboxService;
    recipient: string;
    sender: string;
  } {
    const users = new FakeRepository<User>();
    const recipient = compressedPublicKey();
    const sender = compressedPublicKey();
    void users.save({ publicKey: recipient } as never);
    const service = new MailboxService(
      repo,
      users as never,
      db.dataSource,
      new IdentityService(),
      new FakeClock(),
      fakeConfig({
        MAILBOX_PENDING_CAP: '1000',
        DB_ADVISORY_LOCK_TIMEOUT_MS: String(lockTimeoutMs),
      }).service
    );
    return { service, recipient, sender };
  }

  /** Hold a recipient's advisory lock in an open transaction on one pooled connection. */
  async function holdRecipientLock(recipient: string): Promise<() => Promise<void>> {
    const runner = db.dataSource.createQueryRunner();
    await runner.connect();
    await runner.startTransaction();
    await runner.query('SELECT pg_advisory_xact_lock($1::bigint)', [
      recipientLockKey(recipient).toString(),
    ]);
    return async () => {
      await runner.rollbackTransaction();
      await runner.release();
    };
  }

  function saturate(
    service: MailboxService,
    recipient: string,
    sender: string
  ): Promise<unknown>[] {
    return Array.from({ length: RACERS }, (_, i) =>
      service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: `sat-${i}`,
      })
    );
  }

  it('bounds waiters: saturating same-recipient posts return a retryable 503 while an unrelated query still gets a connection', async () => {
    const { service, recipient, sender } = buildService(300);
    const releaseHolder = await holdRecipientLock(recipient);
    try {
      const racers = saturate(service, recipient, sender);

      // The waiters fill the pool, but each aborts at lock_timeout and frees its
      // connection, so an unrelated query still gets served.
      await expect(db.dataSource.query('SELECT 1')).resolves.toBeDefined();

      const outcomes = await Promise.allSettled(racers);
      const unavailable = outcomes.filter(
        (o) => o.status === 'rejected' && o.reason instanceof ServiceUnavailableException
      );
      expect(unavailable).toHaveLength(RACERS);
    } finally {
      await releaseHolder();
    }
  });

  it('negative control — with the wait unbounded, saturating waiters starve the pool and an unrelated query cannot get a connection', async () => {
    const { service, recipient, sender } = buildService(0);
    const releaseHolder = await holdRecipientLock(recipient);
    const racers = saturate(service, recipient, sender);
    try {
      // Give the waiters time to occupy every pooled connection.
      await delay(300);
      const unrelated = db.dataSource.query('SELECT 1');
      expect(await settledWithin(unrelated, 800)).toBe('pending');

      // Release the holder so the waiters drain and the query completes.
      await releaseHolder();
      await expect(unrelated).resolves.toBeDefined();
    } finally {
      await Promise.allSettled(racers);
    }
  });
});
