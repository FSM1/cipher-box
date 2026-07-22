import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { secp256k1 } from '@noble/curves/secp256k1';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IdentityService } from '../auth/services/identity.service';
import { Clock, SystemClock } from '../common/clock';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { MailboxMessage } from './entities/mailbox-message.entity';
import { MailboxController } from './mailbox.controller';
import { MailboxService } from './services/mailbox.service';

/**
 * The mailbox HTTP surface re-homed onto a REAL Postgres (#725): the
 * post→poll→ack lifecycle and idempotent replay against real `mailbox_messages`
 * rows, the existence-oracle 404, the per-recipient pending-cap 409, the blob
 * 413, the fail-closed validation 400s, ack ownership scoping, the real
 * per-account 429s (including the rate-limited existence oracle), and the
 * Prometheus route metric. The pending-cap serialization proof stays in the
 * service integration suite; here the wire contract runs end-to-end on real DB.
 */

const SECRET = 'mailbox-http-integration-secret';
const PENDING_CAP = 3;

function base64Blob(bytes: number): string {
  return Buffer.alloc(bytes, 42).toString('base64');
}

function newPublicKey(): string {
  const priv = secp256k1.utils.randomPrivateKey();
  try {
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  } finally {
    priv.fill(0);
  }
}

describe('mailbox HTTP surface (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;

    db = await createIntegrationDatabase({ poolMax: 10 });
    ctx = await createHttpIntegrationApp({
      db,
      jwtSecret: SECRET,
      entities: [User, MailboxMessage],
      controllers: [MailboxController],
      providers: [
        MailboxService,
        IdentityService,
        JwtAuthGuard,
        { provide: Clock, useClass: SystemClock },
        {
          provide: ConfigService,
          useValue: fakeConfig({
            MAILBOX_PENDING_CAP: String(PENDING_CAP),
            DB_ADVISORY_LOCK_TIMEOUT_MS: '0',
          }).service,
        },
      ],
    });
    jwt = ctx.app.get(JwtService);
  });

  afterAll(async () => {
    await ctx?.app.close();
    await db?.teardown();
    if (priorJwtSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = priorJwtSecret;
    }
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE users, mailbox_messages CASCADE');
  });

  const http = () => ctx.http;

  /** Seed a user account and mint a valid access token for it. */
  async function account(): Promise<{ publicKey: string; token: string }> {
    const publicKey = newPublicKey();
    const user = await db.dataSource.getRepository(User).save({ publicKey, byo: false });
    const token = await jwt.signAsync({ sub: user.id, publicKey }, { secret: SECRET });
    return { publicKey, token };
  }

  describe('post → poll → ack lifecycle', () => {
    it('delivers a sealed blob end-to-end and hard-deletes on ack', async () => {
      const sender = await account();
      const recipient = await account();
      const blob = base64Blob(128);

      const posted = await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: recipient.publicKey, blob, idempotencyKey: 'life-1' })
        .expect(201);
      expect(posted.body.id).toBeTruthy();

      const polled = await request(http())
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(polled.body.messages).toHaveLength(1);
      expect(polled.body.messages[0]).toEqual({
        id: posted.body.id,
        receivedAt: expect.any(String),
        blob,
      });

      await request(http())
        .delete(`/mailbox/messages/${posted.body.id}`)
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);

      const afterAck = await request(http())
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(afterAck.body.messages).toHaveLength(0);
    });

    it('replays idempotently: the same key returns the original id, no duplicate', async () => {
      const sender = await account();
      const recipient = await account();
      const body = {
        recipientPublicKey: recipient.publicKey,
        blob: base64Blob(64),
        idempotencyKey: 'idem-1',
      };
      const first = await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send(body)
        .expect(201);
      const second = await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send(body)
        .expect(201);
      expect(second.body.id).toBe(first.body.id);

      const polled = await request(http())
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(polled.body.messages).toHaveLength(1);
    });
  });

  describe('rejections', () => {
    it('rejects a post to an unknown recipient with 404 (the existence oracle)', async () => {
      const sender = await account();
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: newPublicKey(), blob: base64Blob(64), idempotencyKey: 'x' })
        .expect(404);
    });

    it('rejects new posts once the per-recipient pending cap is full (reject-new)', async () => {
      const sender = await account();
      const recipient = await account();
      for (let i = 0; i < PENDING_CAP; i += 1) {
        await request(http())
          .post('/mailbox/messages')
          .set('Authorization', `Bearer ${sender.token}`)
          .send({
            recipientPublicKey: recipient.publicKey,
            blob: base64Blob(64),
            idempotencyKey: `c${i}`,
          })
          .expect(201);
      }
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(64),
          idempotencyKey: 'over',
        })
        .expect(409);
    });

    it('rejects a blob larger than 8 KiB with 413', async () => {
      const sender = await account();
      const recipient = await account();
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(8193),
          idempotencyKey: 'big',
        })
        .expect(413);
    });

    it('rejects malformed bodies and unexpected properties with 400', async () => {
      const sender = await account();
      const recipient = await account();
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: 'not-hex', blob: base64Blob(16), idempotencyKey: 'x' })
        .expect(400);
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: 'not base64!!',
          idempotencyKey: 'x',
        })
        .expect(400);
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'x',
          senderPublicKey: 'never-send-this',
        })
        .expect(400);
    });

    it('requires authentication on every route', async () => {
      const recipient = await account();
      await request(http())
        .post('/mailbox/messages')
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'x',
        })
        .expect(401);
      await request(http()).get('/mailbox/messages').expect(401);
      await request(http()).delete('/mailbox/messages/some-id').expect(401);
    });
  });

  describe('ownership scoping', () => {
    it('will not let one account ack another account message', async () => {
      const sender = await account();
      const recipient = await account();
      const attacker = await account();
      const posted = await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(32),
          idempotencyKey: 'own',
        })
        .expect(201);

      // The attacker ack is idempotent-success but must not delete the row.
      await request(http())
        .delete(`/mailbox/messages/${posted.body.id}`)
        .set('Authorization', `Bearer ${attacker.token}`)
        .expect(200);

      const stillThere = await request(http())
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(stillThere.body.messages).toHaveLength(1);
    });
  });

  describe('rate limiting (real 429s)', () => {
    it('rate-limits the per-sender post surface — including the existence oracle', async () => {
      const sender = await account();
      const limit = THROTTLE_SURFACES.mailboxPost.default.limit;
      // Probe unknown recipients: each is a 404, but the throttler counts them,
      // so an account cannot brute-force the pubkey existence oracle.
      for (let i = 0; i < limit; i += 1) {
        await request(http())
          .post('/mailbox/messages')
          .set('Authorization', `Bearer ${sender.token}`)
          .send({
            recipientPublicKey: newPublicKey(),
            blob: base64Blob(16),
            idempotencyKey: `o${i}`,
          })
          .expect(404);
      }
      const throttled = await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: newPublicKey(), blob: base64Blob(16), idempotencyKey: 'last' })
        .expect(429);
      expect(throttled.headers['retry-after']).toBeDefined();
    });

    it('keys the post limit by account: a second sender is unaffected', async () => {
      const fresh = await account();
      const recipient = await account();
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${fresh.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'fresh',
        })
        .expect(201);
    });
  });

  describe('metrics', () => {
    it('records the mailbox endpoints in the Prometheus registry', async () => {
      const sender = await account();
      const recipient = await account();
      await request(http())
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'm',
        })
        .expect(201);
      const res = await request(http()).get('/metrics').expect(200);
      expect(res.text).toMatch(/http_requests_total\{[^}]*route="\/mailbox\/messages"[^}]*\} \d+/);
    });
  });
});
