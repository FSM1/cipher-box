import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash, randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { IdentityTokenService } from '../auth/services/identity-token.service';
import { AcceleratorToken } from '../auth/entities/accelerator-token.entity';
import { AcceleratorTokenService } from '../auth/services/accelerator-token.service';
import { TokenService } from '../auth/services/token.service';
import { Clock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { createTestDeviceKey, TestDeviceKey } from '../testing/device-keys';
import { FakeClock, fakeConfig } from '../testing/fakes';
import {
  createHttpIntegrationApp,
  HttpIntegrationApp,
  randomCompressedPublicKey,
  seedAccount,
} from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { DeviceApprovalSessionController } from './device-approval-session.controller';
import { DeviceApprovalController } from './device-approval.controller';
import {
  approvalRequestPayload,
  approvalResponsePayload,
  deviceRegistrationPayload,
  verifyDeviceSignature,
} from './device-signature';
import { DeviceController } from './device.controller';
import { AccountDevice } from './entities/account-device.entity';
import { DeviceApproval } from './entities/device-approval.entity';
import { AccountDeviceService } from './services/account-device.service';
import { DeviceApprovalService } from './services/device-approval.service';

/**
 * The bound rendezvous (ADR 0009) end-to-end over HTTP against a REAL Postgres:
 * register → scoped session → request → pending → respond → collect, the hard
 * deletes at collection and expiry, the scope wall around the pre-reconstruction
 * token, the signature binding on both halves, and the zero-knowledge property
 * asserted against the live schema and the stored bytes.
 */

const PENDING_CAP = 3;
const TTL_MS = 5 * 60 * 1000;

/** Every column `device_approvals` has; the set itself is the zero-knowledge claim. */
const DEVICE_APPROVAL_COLUMNS = [
  'created_at',
  'ephemeral_public_key',
  'expires_at',
  'id',
  'request_signature',
  'requester_device_public_key',
  'responder_device_public_key',
  'response_signature',
  'sealed_factor',
  'status',
  'user_id',
];

interface Enrolled {
  userId: string;
  publicKey: string;
  /** Full session token — the approver side. */
  token: string;
  identitySubject: string;
  /** The registered approver device. */
  device: TestDeviceKey;
}

describe('device-approval HTTP surface (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let jwt: JwtService;
  let clock: FakeClock;
  let identityTokens: IdentityTokenService;
  let approvals: DeviceApprovalService;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    clock = new FakeClock();
    ctx = await createHttpIntegrationApp({
      db,
      // The rendezvous surfaces cap at 3 requests/min; the throttler is not under
      // test here and would 429 valid steps of the lifecycle.
      withOps: false,
      entities: [User, AccountDevice, DeviceApproval, RefreshToken, AcceleratorToken],
      controllers: [DeviceController, DeviceApprovalSessionController, DeviceApprovalController],
      providers: [
        AccountDeviceService,
        DeviceApprovalService,
        IdentityTokenService,
        TokenService,
        AcceleratorTokenService,
        JwtAuthGuard,
        { provide: Clock, useValue: clock },
        { provide: Entropy, useClass: SystemEntropy },
        {
          provide: ConfigService,
          useValue: fakeConfig({
            NODE_ENV: 'test',
            DB_ADVISORY_LOCK_TIMEOUT_MS: '0',
            DEVICE_APPROVAL_PENDING_CAP: String(PENDING_CAP),
            DEVICE_APPROVAL_TTL_MS: String(TTL_MS),
          }).service,
        },
      ],
    });
    jwt = ctx.app.get(JwtService);
    identityTokens = ctx.app.get(IdentityTokenService);
    approvals = ctx.app.get(DeviceApprovalService);
  });

  afterAll(async () => {
    await ctx?.close();
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query(
      'TRUNCATE TABLE users, identity_subjects, account_devices, device_approvals, refresh_tokens CASCADE'
    );
  });

  const http = () => ctx.http;

  /**
   * A token for a subject this API has resolved, as `POST /auth/identity/*`
   * always mints: `account_devices.identity_subject_id` references the row.
   */
  async function identityToken(subject: string): Promise<string> {
    await db.dataSource.query(
      `INSERT INTO identity_subjects (id, kind, identifier_hash) VALUES ($1, 'google', $2)
       ON CONFLICT ("id") DO NOTHING`,
      [subject, createHash('sha256').update(subject).digest('hex')]
    );
    return (await identityTokens.sign({ subject, method: 'google' })).token;
  }

  /** An account with one registered approver device, reachable by its identity. */
  async function enroll(label = 'approver'): Promise<Enrolled> {
    const account = await seedAccount(db, jwt);
    const identitySubject = randomUUID();
    const device = createTestDeviceKey();
    await request(http())
      .post('/devices')
      .set('Authorization', `Bearer ${account.token}`)
      .send({
        publicKey: device.publicKey,
        signature: device.sign(deviceRegistrationPayload(account.userId, device.publicKey)),
        identityToken: await identityToken(identitySubject),
        label,
      })
      .expect(201);
    return { ...account, identitySubject, device };
  }

  /** A second approver on an existing account, under its own identity subject. */
  async function registerDevice(account: Enrolled, label: string): Promise<TestDeviceKey> {
    const device = createTestDeviceKey();
    await request(http())
      .post('/devices')
      .set('Authorization', `Bearer ${account.token}`)
      .send({
        publicKey: device.publicKey,
        signature: device.sign(deviceRegistrationPayload(account.userId, device.publicKey)),
        identityToken: await identityToken(randomUUID()),
        label,
      })
      .expect(201);
    return device;
  }

  /** The pre-reconstruction token a new device gets by presenting the identity. */
  async function scopedToken(identitySubject: string): Promise<string> {
    const res = await request(http())
      .post('/device-approval/session')
      .send({ identityToken: await identityToken(identitySubject) })
      .expect(200);
    return res.body.accessToken;
  }

  async function openRendezvous(
    token: string,
    device: TestDeviceKey,
    ephemeralPublicKey = randomCompressedPublicKey()
  ): Promise<{ requestId: string; ephemeralPublicKey: string; expiresAt: string }> {
    const res = await request(http())
      .post('/device-approval/requests')
      .set('Authorization', `Bearer ${token}`)
      .send({
        devicePublicKey: device.publicKey,
        ephemeralPublicKey,
        signature: device.sign(approvalRequestPayload(device.publicKey, ephemeralPublicKey)),
      })
      .expect(201);
    return {
      requestId: res.body.requestId,
      ephemeralPublicKey,
      expiresAt: res.body.expiresAt,
    };
  }

  /** `ephemeralPublicKey` is what the signature covers — the server uses the stored one. */
  function respondBody(input: {
    device: TestDeviceKey;
    requestId: string;
    decision: 'approve' | 'deny';
    ephemeralPublicKey: string;
    sealedFactor?: string;
  }) {
    return {
      decision: input.decision,
      devicePublicKey: input.device.publicKey,
      signature: input.device.sign(
        approvalResponsePayload({
          devicePublicKey: input.device.publicKey,
          requestId: input.requestId,
          decision: input.decision,
          ephemeralPublicKey: input.ephemeralPublicKey,
          sealedFactor: input.sealedFactor ?? '',
        })
      ),
      ...(input.sealedFactor !== undefined ? { sealedFactor: input.sealedFactor } : {}),
    };
  }

  function sealedBlob(bytes: number, fill = 0xa7): string {
    return Buffer.alloc(bytes, fill).toString('base64');
  }

  async function approvalRowCount(): Promise<number> {
    const rows = await db.dataSource.query('SELECT count(*)::int AS count FROM device_approvals');
    return rows[0].count;
  }

  describe('the bound rendezvous end to end', () => {
    it('carries a sealed factor from a registered approver to the new device', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);

      const opened = await openRendezvous(scoped, newDevice);
      expect(opened.requestId).toBeTruthy();

      const pending = await request(http())
        .get('/device-approval/pending')
        .set('Authorization', `Bearer ${account.token}`)
        .expect(200);
      expect(pending.body.requests).toHaveLength(1);
      expect(pending.body.requests[0]).toEqual({
        requestId: opened.requestId,
        requesterDevicePublicKey: newDevice.publicKey,
        ephemeralPublicKey: opened.ephemeralPublicKey,
        requestSignature: newDevice.sign(
          approvalRequestPayload(newDevice.publicKey, opened.ephemeralPublicKey)
        ),
        createdAt: expect.any(String),
        expiresAt: opened.expiresAt,
      });

      const sealedFactor = sealedBlob(125);
      const body = respondBody({
        device: account.device,
        requestId: opened.requestId,
        decision: 'approve',
        ephemeralPublicKey: opened.ephemeralPublicKey,
        sealedFactor,
      });
      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(body)
        .expect(200);

      const collected = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(collected.body).toEqual({
        status: 'approved',
        ephemeralPublicKey: opened.ephemeralPublicKey,
        expiresAt: opened.expiresAt,
        sealedFactor,
        responderDevicePublicKey: account.device.publicKey,
        responseSignature: body.signature,
      });

      // The check a real requester makes before opening the seal (ADR 0009 D4):
      // rebuild the payload from what was SERVED, so any field the relay altered
      // — the sealed bytes included — breaks the approver's signature.
      expect(
        verifyDeviceSignature(
          collected.body.responderDevicePublicKey,
          collected.body.responseSignature,
          approvalResponsePayload({
            devicePublicKey: collected.body.responderDevicePublicKey,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: collected.body.ephemeralPublicKey,
            sealedFactor: collected.body.sealedFactor,
          })
        )
      ).toBe(true);
    });

    it('binds the served approval signature to the served sealed bytes', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);
      const sealedFactor = sealedBlob(125);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor,
          })
        )
        .expect(200);

      const collected = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);

      const rebuild = (overrides: Partial<Parameters<typeof approvalResponsePayload>[0]>) =>
        approvalResponsePayload({
          devicePublicKey: collected.body.responderDevicePublicKey,
          requestId: opened.requestId,
          decision: 'approve',
          ephemeralPublicKey: collected.body.ephemeralPublicKey,
          sealedFactor: collected.body.sealedFactor,
          ...overrides,
        });

      for (const tampered of [
        rebuild({ sealedFactor: sealedBlob(125, 0xa8) }),
        rebuild({ sealedFactor: collected.body.sealedFactor.replace(/=+$/, '') }),
        rebuild({ decision: 'deny' }),
        rebuild({ ephemeralPublicKey: randomCompressedPublicKey() }),
        rebuild({ requestId: randomUUID() }),
      ]) {
        expect(
          verifyDeviceSignature(
            collected.body.responderDevicePublicKey,
            collected.body.responseSignature,
            tampered
          )
        ).toBe(false);
      }
    });

    it('serves a settled rendezvous once: the second poll 404s and no row survives', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor: sealedBlob(96),
          })
        )
        .expect(200);

      await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(404);
      expect(await approvalRowCount()).toBe(0);
    });

    it('round-trips a denial and deletes its row after one collection', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'deny',
            ephemeralPublicKey: opened.ephemeralPublicKey,
          })
        )
        .expect(200);

      const collected = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(collected.body.status).toBe('denied');
      expect(collected.body.sealedFactor).toBeUndefined();
      expect(collected.body.responderDevicePublicKey).toBe(account.device.publicKey);

      await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(404);
      expect(await approvalRowCount()).toBe(0);
    });
  });

  describe('concurrency', () => {
    it('serves a settled rendezvous to exactly one of two simultaneous polls', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);
      const sealedFactor = sealedBlob(125);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor,
          })
        )
        .expect(200);

      const poll = () =>
        request(http())
          .get(`/device-approval/requests/${opened.requestId}`)
          .set('Authorization', `Bearer ${scoped}`);
      const results = await Promise.all([poll(), poll()]);

      expect(results.map((res) => res.status).sort()).toEqual([200, 404]);
      const served = results.filter((res) => res.status === 200);
      expect(served).toHaveLength(1);
      expect(served[0].body.sealedFactor).toBe(sealedFactor);
      // The delete IS the claim: the loser walks away with nothing, and the
      // sealed bytes are unreachable to either of them afterwards.
      expect(results.find((res) => res.status === 404)?.body.sealedFactor).toBeUndefined();
      expect(await approvalRowCount()).toBe(0);
    });

    it('lets exactly one of two registered devices answer the same rendezvous', async () => {
      const account = await enroll('first');
      const second = await registerDevice(account, 'second');
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      const sealed = {
        [account.device.publicKey]: sealedBlob(96, 0x11),
        [second.publicKey]: sealedBlob(96, 0x22),
      };
      const respond = (device: TestDeviceKey) =>
        request(http())
          .post(`/device-approval/requests/${opened.requestId}/respond`)
          .set('Authorization', `Bearer ${account.token}`)
          .send(
            respondBody({
              device,
              requestId: opened.requestId,
              decision: 'approve',
              ephemeralPublicKey: opened.ephemeralPublicKey,
              sealedFactor: sealed[device.publicKey],
            })
          );
      const results = await Promise.all([respond(account.device), respond(second)]);

      expect(results.map((res) => res.status).sort()).toEqual([200, 404]);

      // One answer stands whole: the winner's key and its own sealed bytes.
      const collected = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(collected.body.sealedFactor).toBe(sealed[collected.body.responderDevicePublicKey]);
      expect(await approvalRowCount()).toBe(0);
    });
  });

  describe('expiry', () => {
    it('404s an expired rendezvous and leaves no row behind', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);
      expect(await approvalRowCount()).toBe(1);

      clock.advanceMs(TTL_MS + 1);

      await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(404);
      expect(await approvalRowCount()).toBe(0);
    });

    it('sweepExpired deletes exactly the expired rows and reports the count', async () => {
      const account = await enroll();
      const repo = db.dataSource.getRepository(DeviceApproval);
      const requester = createTestDeviceKey();
      const now = clock.now();

      const row = (offsetMs: number) => {
        const ephemeralPublicKey = randomCompressedPublicKey();
        return {
          userId: account.userId,
          requesterDevicePublicKey: requester.publicKey,
          ephemeralPublicKey,
          requestSignature: requester.sign(
            approvalRequestPayload(requester.publicKey, ephemeralPublicKey)
          ),
          status: 'pending' as const,
          sealedFactor: null,
          responderDevicePublicKey: null,
          responseSignature: null,
          createdAt: now,
          expiresAt: new Date(now.getTime() + offsetMs),
        };
      };

      const expired = await repo.save([row(-60_000), row(-1_000), row(-1)]);
      const live = await repo.save([row(60_000), row(120_000)]);

      expect(await approvals.sweepExpired()).toBe(expired.length);

      const remaining = await repo.find();
      expect(remaining.map((entry) => entry.id).sort()).toEqual(
        live.map((entry) => entry.id).sort()
      );
    });
  });

  describe('the pre-reconstruction token reaches the rendezvous and nothing else', () => {
    it('opens, polls and abandons a rendezvous', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);

      const opened = await openRendezvous(scoped, newDevice);
      const polled = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(polled.body.status).toBe('pending');

      await request(http())
        .delete(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(await approvalRowCount()).toBe(0);
    });

    it('is refused with 403 on every approval and registry route', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .get('/device-approval/pending')
        .set('Authorization', `Bearer ${scoped}`)
        .expect(403);
      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${scoped}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor: sealedBlob(64),
          })
        )
        .expect(403);
      await request(http())
        .post('/devices')
        .set('Authorization', `Bearer ${scoped}`)
        .send({
          publicKey: newDevice.publicKey,
          signature: newDevice.sign(deviceRegistrationPayload(account.userId, newDevice.publicKey)),
          identityToken: await identityToken(account.identitySubject),
        })
        .expect(403);
      await request(http()).get('/devices').set('Authorization', `Bearer ${scoped}`).expect(403);
      await request(http())
        .delete(`/devices/${randomUUID()}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(403);

      // The refusal is a wall, not a side effect: nothing was registered.
      const registered = await request(http())
        .get('/devices')
        .set('Authorization', `Bearer ${account.token}`)
        .expect(200);
      expect(registered.body.devices).toHaveLength(1);
      expect(registered.body.devices[0].publicKey).toBe(account.device.publicKey);
    });
  });

  describe('signature binding', () => {
    it('401s a request whose signature covers a different ephemeral key', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const offered = randomCompressedPublicKey();

      await request(http())
        .post('/device-approval/requests')
        .set('Authorization', `Bearer ${scoped}`)
        .send({
          devicePublicKey: newDevice.publicKey,
          ephemeralPublicKey: offered,
          signature: newDevice.sign(
            approvalRequestPayload(newDevice.publicKey, randomCompressedPublicKey())
          ),
        })
        .expect(401);
      expect(await approvalRowCount()).toBe(0);
    });

    it('401s a request signed by a device key other than the one it names', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const impostor = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const ephemeralPublicKey = randomCompressedPublicKey();

      await request(http())
        .post('/device-approval/requests')
        .set('Authorization', `Bearer ${scoped}`)
        .send({
          devicePublicKey: newDevice.publicKey,
          ephemeralPublicKey,
          signature: impostor.sign(approvalRequestPayload(newDevice.publicKey, ephemeralPublicKey)),
        })
        .expect(401);
      expect(await approvalRowCount()).toBe(0);
    });

    it('401s a response signed over an ephemeral key other than the stored one', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: randomCompressedPublicKey(),
            sealedFactor: sealedBlob(64),
          })
        )
        .expect(401);

      const stillPending = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(stillPending.body.status).toBe('pending');
    });

    it('401s a response from a device not registered to the account', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const stranger = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: stranger,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor: sealedBlob(64),
          })
        )
        .expect(401);

      const stillPending = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(stillPending.body.status).toBe('pending');
    });
  });

  describe('the API never holds an unsealed factor key', () => {
    it('has no column that could hold a plaintext factor, and sealed_factor is nullable bytea', async () => {
      const columns = await db.dataSource.query(
        `SELECT column_name, data_type, is_nullable FROM information_schema.columns
           WHERE table_schema = 'public' AND table_name = 'device_approvals'
           ORDER BY column_name`
      );
      expect(columns.map((column: { column_name: string }) => column.column_name)).toEqual(
        DEVICE_APPROVAL_COLUMNS
      );
      expect(
        columns.find((column: { column_name: string }) => column.column_name === 'sealed_factor')
      ).toMatchObject({ data_type: 'bytea', is_nullable: 'YES' });
    });

    it('stores the approver bytes verbatim and relays them unchanged', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);
      const sealedFactor = Buffer.from(
        Array.from({ length: 200 }, (_, index) => (index * 37 + 11) & 0xff)
      ).toString('base64');

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor,
          })
        )
        .expect(200);

      const stored = await db.dataSource.query(
        'SELECT sealed_factor FROM device_approvals WHERE id = $1',
        [opened.requestId]
      );
      expect(stored[0].sealed_factor.equals(Buffer.from(sealedFactor, 'base64'))).toBe(true);

      const collected = await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${scoped}`)
        .expect(200);
      expect(collected.body.sealedFactor).toBe(sealedFactor);
    });
  });

  describe('refusals', () => {
    it('400s self-approval even when the requester signature is valid', async () => {
      const account = await enroll();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, account.device);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor: sealedBlob(64),
          })
        )
        .expect(400);
    });

    it('409s once the account is at its pending-rendezvous cap', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      for (let i = 0; i < PENDING_CAP; i += 1) {
        await openRendezvous(scoped, newDevice);
      }
      const ephemeralPublicKey = randomCompressedPublicKey();
      await request(http())
        .post('/device-approval/requests')
        .set('Authorization', `Bearer ${scoped}`)
        .send({
          devicePublicKey: newDevice.publicKey,
          ephemeralPublicKey,
          signature: newDevice.sign(
            approvalRequestPayload(newDevice.publicKey, ephemeralPublicKey)
          ),
        })
        .expect(409);
      expect(await approvalRowCount()).toBe(PENDING_CAP);
    });

    it('413s a sealed factor over 1 KiB', async () => {
      const account = await enroll();
      const newDevice = createTestDeviceKey();
      const scoped = await scopedToken(account.identitySubject);
      const opened = await openRendezvous(scoped, newDevice);

      await request(http())
        .post(`/device-approval/requests/${opened.requestId}/respond`)
        .set('Authorization', `Bearer ${account.token}`)
        .send(
          respondBody({
            device: account.device,
            requestId: opened.requestId,
            decision: 'approve',
            ephemeralPublicKey: opened.ephemeralPublicKey,
            sealedFactor: sealedBlob(1025),
          })
        )
        .expect(413);
    });

    it('404s a session for an identity with no registered device', async () => {
      await request(http())
        .post('/device-approval/session')
        .send({ identityToken: await identityToken(randomUUID()) })
        .expect(404);
    });

    it('401s a session for a garbage identity token', async () => {
      await request(http())
        .post('/device-approval/session')
        .send({ identityToken: 'not.a.token' })
        .expect(401);
    });

    it('404s a request id belonging to another account', async () => {
      const owner = await enroll('owner');
      const other = await enroll('other');
      const newDevice = createTestDeviceKey();
      const opened = await openRendezvous(await scopedToken(owner.identitySubject), newDevice);

      await request(http())
        .get(`/device-approval/requests/${opened.requestId}`)
        .set('Authorization', `Bearer ${await scopedToken(other.identitySubject)}`)
        .expect(404);
      expect(await approvalRowCount()).toBe(1);
    });
  });
});
