import { INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { getDataSourceToken, getRepositoryToken } from '@nestjs/typeorm';
import { secp256k1 } from '@noble/curves/secp256k1';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IdentityService } from '../auth/services/identity.service';
import { Clock, SystemClock } from '../common/clock';
import { OpsModule } from '../ops/ops.module';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { FakeDataSource } from '../testing/fake-data-source';
import { FakeRepository } from '../testing/fake-repo';
import { fakeConfig } from '../testing/fakes';
import { MailboxController } from './mailbox.controller';
import { MailboxMessage } from './entities/mailbox-message.entity';
import { MailboxService } from './services/mailbox.service';

const SECRET = 'mailbox-test-secret';
const PENDING_CAP = 3;

function base64Blob(bytes: number): string {
  return Buffer.alloc(bytes, 42).toString('base64');
}

describe('mailbox HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let userRepo: FakeRepository<User>;
  let messageRepo: FakeRepository<MailboxMessage>;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;

  beforeAll(async () => {
    // The account-keyed throttler only trusts a `sub` from a token it can
    // verify; align its HS256 secret with the one these tokens are signed with.
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;

    userRepo = new FakeRepository<User>();
    messageRepo = new FakeRepository<MailboxMessage>();
    jwt = new JwtService();

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        OpsModule,
        JwtModule.register({ secret: SECRET, signOptions: { expiresIn: 900 } }),
      ],
      controllers: [MailboxController],
      providers: [
        MailboxService,
        IdentityService,
        JwtAuthGuard,
        { provide: Clock, useClass: SystemClock },
        {
          provide: ConfigService,
          useValue: fakeConfig({ MAILBOX_PENDING_CAP: String(PENDING_CAP) }).service,
        },
        { provide: getRepositoryToken(User), useValue: userRepo },
        { provide: getRepositoryToken(MailboxMessage), useValue: messageRepo },
        {
          provide: getDataSourceToken(),
          useValue: new FakeDataSource(messageRepo as never, [[User, userRepo as never]]),
        },
      ],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
    if (priorJwtSecret === undefined) {
      delete process.env.JWT_SECRET;
    } else {
      process.env.JWT_SECRET = priorJwtSecret;
    }
  });

  /** Seed a user account and mint a valid access token for it. */
  async function account(): Promise<{ publicKey: string; token: string }> {
    const priv = secp256k1.utils.randomPrivateKey();
    const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
    const user = await userRepo.save({ publicKey } as never);
    const token = await jwt.signAsync({ sub: user.id, publicKey }, { secret: SECRET });
    return { publicKey, token };
  }

  function unknownPublicKey(): string {
    const priv = secp256k1.utils.randomPrivateKey();
    return Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
  }

  describe('post → poll → ack lifecycle', () => {
    it('delivers a sealed blob end-to-end and hard-deletes on ack', async () => {
      const sender = await account();
      const recipient = await account();
      const blob = base64Blob(128);

      const posted = await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: recipient.publicKey, blob, idempotencyKey: 'life-1' })
        .expect(201);
      expect(posted.body.id).toBeTruthy();

      const polled = await request(http)
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(polled.body.messages).toHaveLength(1);
      expect(polled.body.messages[0]).toEqual({
        id: posted.body.id,
        receivedAt: expect.any(String),
        blob,
      });

      await request(http)
        .delete(`/mailbox/messages/${posted.body.id}`)
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);

      const afterAck = await request(http)
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
      const first = await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send(body)
        .expect(201);
      const second = await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send(body)
        .expect(201);
      expect(second.body.id).toBe(first.body.id);

      const polled = await request(http)
        .get('/mailbox/messages')
        .set('Authorization', `Bearer ${recipient.token}`)
        .expect(200);
      expect(polled.body.messages).toHaveLength(1);
    });
  });

  describe('rejections', () => {
    it('rejects a post to an unknown recipient with 404 (the existence oracle)', async () => {
      const sender = await account();
      await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: unknownPublicKey(), blob: base64Blob(64), idempotencyKey: 'x' })
        .expect(404);
    });

    it('rejects new posts once the per-recipient pending cap is full (reject-new)', async () => {
      const sender = await account();
      const recipient = await account();
      for (let i = 0; i < PENDING_CAP; i += 1) {
        await request(http)
          .post('/mailbox/messages')
          .set('Authorization', `Bearer ${sender.token}`)
          .send({
            recipientPublicKey: recipient.publicKey,
            blob: base64Blob(64),
            idempotencyKey: `c${i}`,
          })
          .expect(201);
      }
      await request(http)
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
      await request(http)
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
      await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({ recipientPublicKey: 'not-hex', blob: base64Blob(16), idempotencyKey: 'x' })
        .expect(400);
      await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: 'not base64!!',
          idempotencyKey: 'x',
        })
        .expect(400);
      await request(http)
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
      await request(http)
        .post('/mailbox/messages')
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'x',
        })
        .expect(401);
      await request(http).get('/mailbox/messages').expect(401);
      await request(http).delete('/mailbox/messages/some-id').expect(401);
    });
  });

  describe('ownership scoping', () => {
    it('will not let one account ack another account message', async () => {
      const sender = await account();
      const recipient = await account();
      const attacker = await account();
      const posted = await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(32),
          idempotencyKey: 'own',
        })
        .expect(201);

      // The attacker ack is idempotent-success but must not delete the row.
      await request(http)
        .delete(`/mailbox/messages/${posted.body.id}`)
        .set('Authorization', `Bearer ${attacker.token}`)
        .expect(200);

      const stillThere = await request(http)
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
        await request(http)
          .post('/mailbox/messages')
          .set('Authorization', `Bearer ${sender.token}`)
          .send({
            recipientPublicKey: unknownPublicKey(),
            blob: base64Blob(16),
            idempotencyKey: `o${i}`,
          })
          .expect(404);
      }
      const throttled = await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: unknownPublicKey(),
          blob: base64Blob(16),
          idempotencyKey: 'last',
        })
        .expect(429);
      expect(throttled.headers['retry-after']).toBeDefined();
    });

    it('keys the post limit by account: a second sender is unaffected', async () => {
      const fresh = await account();
      const recipient = await account();
      await request(http)
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
      await request(http)
        .post('/mailbox/messages')
        .set('Authorization', `Bearer ${sender.token}`)
        .send({
          recipientPublicKey: recipient.publicKey,
          blob: base64Blob(16),
          idempotencyKey: 'm',
        })
        .expect(201);
      const res = await request(http).get('/metrics').expect(200);
      expect(res.text).toMatch(/http_requests_total\{[^}]*route="\/mailbox\/messages"[^}]*\} \d+/);
    });
  });
});
