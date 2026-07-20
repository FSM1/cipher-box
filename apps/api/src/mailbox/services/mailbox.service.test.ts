import { ConflictException, NotFoundException, PayloadTooLargeException } from '@nestjs/common';
import { secp256k1 } from '@noble/curves/secp256k1';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IdentityService } from '../../auth/services/identity.service';
import { User } from '../../auth/entities/user.entity';
import { FakeRepository } from '../../testing/fake-repo';
import { FakeClock, fakeConfig } from '../../testing/fakes';
import { MailboxMessage } from '../entities/mailbox-message.entity';
import { MailboxService } from './mailbox.service';

function newPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
}

function base64Blob(bytes: number): string {
  return Buffer.alloc(bytes, 7).toString('base64');
}

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

describe('MailboxService', () => {
  let messages: FakeRepository<MailboxMessage>;
  let users: FakeRepository<User>;
  let clock: FakeClock;
  let service: MailboxService;
  let recipient: string;
  let sender: string;

  function build(config: Record<string, string | undefined> = {}) {
    messages = new FakeRepository<MailboxMessage>();
    users = new FakeRepository<User>();
    clock = new FakeClock();
    service = new MailboxService(
      messages as never,
      users as never,
      new IdentityService(),
      clock,
      fakeConfig(config).service
    );
  }

  beforeEach(async () => {
    build({ MAILBOX_PENDING_CAP: '3' });
    recipient = newPublicKey();
    sender = newPublicKey();
    await users.save({ publicKey: recipient } as never);
  });

  describe('post', () => {
    it('stores a sealed blob for a known recipient and returns an id', async () => {
      const { id } = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'k1',
      });
      expect(id).toBeTruthy();
      expect(messages.rows).toHaveLength(1);
      expect(messages.rows[0].recipientPublicKey).toBe(recipient);
      // The stored blob is the opaque bytes, never a decoded structure.
      expect(Buffer.isBuffer(messages.rows[0].blob)).toBe(true);
    });

    it('rejects a post to an unknown recipient (the rate-limited existence oracle)', async () => {
      await expect(
        service.post(sender, {
          recipientPublicKey: newPublicKey(),
          blob: base64Blob(64),
          idempotencyKey: 'k1',
        })
      ).rejects.toBeInstanceOf(NotFoundException);
      expect(messages.rows).toHaveLength(0);
    });

    it('normalizes an uncompressed recipient key to the account it belongs to', async () => {
      const priv = secp256k1.utils.randomPrivateKey();
      const compressed = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
      const uncompressed = Buffer.from(secp256k1.getPublicKey(priv, false)).toString('hex');
      await users.save({ publicKey: compressed } as never);
      const { id } = await service.post(sender, {
        recipientPublicKey: uncompressed,
        blob: base64Blob(64),
        idempotencyKey: 'k1',
      });
      expect(id).toBeTruthy();
      expect(messages.rows.at(-1)?.recipientPublicKey).toBe(compressed);
    });

    it('is idempotent per sender: a replay returns the original id without a duplicate row', async () => {
      const first = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'dup',
      });
      const second = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'dup',
      });
      expect(second.id).toBe(first.id);
      expect(messages.rows).toHaveLength(1);
    });

    it('does not collide idempotency keys across different senders', async () => {
      const other = newPublicKey();
      const a = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'shared',
      });
      const b = await service.post(other, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'shared',
      });
      expect(b.id).not.toBe(a.id);
      expect(messages.rows).toHaveLength(2);
    });

    it('rejects a blob larger than 8 KiB', async () => {
      await expect(
        service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(8193),
          idempotencyKey: 'big',
        })
      ).rejects.toBeInstanceOf(PayloadTooLargeException);
      expect(messages.rows).toHaveLength(0);
    });

    it('rejects new posts once the per-recipient pending cap is full (reject-new)', async () => {
      for (let i = 0; i < 3; i += 1) {
        await service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: `k${i}`,
        });
      }
      await expect(
        service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: 'overflow',
        })
      ).rejects.toBeInstanceOf(ConflictException);
      expect(messages.rows).toHaveLength(3);
    });

    it('lets an idempotent replay through even when the mailbox is full', async () => {
      for (let i = 0; i < 3; i += 1) {
        await service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: `k${i}`,
        });
      }
      const replay = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'k0',
      });
      expect(replay.id).toBe(messages.rows[0].id);
      expect(messages.rows).toHaveLength(3);
    });

    it('frees cap room by purging entries past the 90-day TTL before counting', async () => {
      for (let i = 0; i < 3; i += 1) {
        await service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(64),
          idempotencyKey: `k${i}`,
        });
      }
      clock.advanceMs(NINETY_DAYS_MS + 1);
      const fresh = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(64),
        idempotencyKey: 'fresh',
      });
      expect(fresh.id).toBeTruthy();
      // The three expired rows were purged; only the freshly-posted one remains.
      expect(messages.rows).toHaveLength(1);
      expect(messages.rows[0].id).toBe(fresh.id);
    });
  });

  describe('poll', () => {
    it('returns pending messages oldest-first with no sender metadata', async () => {
      await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'a',
      });
      clock.advanceMs(1000);
      await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(20),
        idempotencyKey: 'b',
      });
      const { messages: out } = await service.poll(recipient);
      expect(out).toHaveLength(2);
      expect(new Date(out[0].receivedAt).getTime()).toBeLessThan(
        new Date(out[1].receivedAt).getTime()
      );
      // Only id/receivedAt/blob are exposed — nothing identifies the sender.
      expect(Object.keys(out[0]).sort()).toEqual(['blob', 'id', 'receivedAt']);
      expect(out[0].blob).toBe(base64Blob(10));
    });

    it('returns only the polling recipient own messages', async () => {
      const otherRecipient = newPublicKey();
      await users.save({ publicKey: otherRecipient } as never);
      await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'mine',
      });
      await service.post(sender, {
        recipientPublicKey: otherRecipient,
        blob: base64Blob(10),
        idempotencyKey: 'theirs',
      });
      const { messages: out } = await service.poll(recipient);
      expect(out).toHaveLength(1);
    });

    it('purges and omits messages past the 90-day TTL', async () => {
      await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'old',
      });
      clock.advanceMs(NINETY_DAYS_MS + 1);
      await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'new',
      });
      const { messages: out } = await service.poll(recipient);
      expect(out).toHaveLength(1);
      expect(messages.rows).toHaveLength(1);
    });

    it('caps the batch at the configured poll limit', async () => {
      build({ MAILBOX_PENDING_CAP: '100', MAILBOX_POLL_LIMIT: '2' });
      await users.save({ publicKey: recipient } as never);
      for (let i = 0; i < 5; i += 1) {
        await service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(10),
          idempotencyKey: `k${i}`,
        });
      }
      const { messages: out } = await service.poll(recipient);
      expect(out).toHaveLength(2);
    });
  });

  describe('configuration', () => {
    it('falls back to safe finite bounds when the configured limits are garbage', async () => {
      // A misconfigured limit must fail closed to the default, never to NaN:
      // a NaN poll limit slices to [] (and a NaN pending cap fails open, since
      // `pending >= NaN` is always false). The fallbacks keep both finite.
      build({ MAILBOX_PENDING_CAP: 'not-a-number', MAILBOX_POLL_LIMIT: 'nope' });
      await users.save({ publicKey: recipient } as never);
      for (let i = 0; i < 3; i += 1) {
        await service.post(sender, {
          recipientPublicKey: recipient,
          blob: base64Blob(10),
          idempotencyKey: `k${i}`,
        });
      }
      const { messages: out } = await service.poll(recipient);
      expect(out).toHaveLength(3);
    });
  });

  describe('ack', () => {
    it('hard-deletes the message by id for its recipient', async () => {
      const { id } = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'a',
      });
      await service.ack(recipient, id);
      expect(messages.rows).toHaveLength(0);
    });

    it('will not let one account ack another account message', async () => {
      const attacker = newPublicKey();
      const { id } = await service.post(sender, {
        recipientPublicKey: recipient,
        blob: base64Blob(10),
        idempotencyKey: 'a',
      });
      await service.ack(attacker, id);
      // The row survives: ack is scoped to the caller mailbox.
      expect(messages.rows).toHaveLength(1);
    });

    it('is idempotent: acking a well-formed but already-gone id succeeds', async () => {
      await expect(service.ack(recipient, '00000000-0000-4000-8000-000000000000')).resolves.toEqual(
        { success: true }
      );
    });

    it('returns idempotent success for a malformed id without touching the repo', async () => {
      // A non-uuid id would make the `uuid`-typed column raise 22P02 → a 500;
      // the guard short-circuits to success and never issues the delete.
      const deleteSpy = vi.spyOn(messages, 'delete');
      await expect(service.ack(recipient, 'not-a-uuid')).resolves.toEqual({ success: true });
      expect(deleteSpy).not.toHaveBeenCalled();
    });
  });
});
