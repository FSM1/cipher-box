import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash } from 'node:crypto';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { PinStore } from '../registry/pin-store';
import { fakeConfig } from '../testing/fakes';
import {
  createHttpIntegrationApp,
  HttpIntegrationApp,
  randomCompressedPublicKey,
  seedAccount,
} from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { ContentController } from './content.controller';
import { ContentService } from './content.service';
import { QUOTA_EXCEEDED, UPLOAD_TOO_LARGE } from './upload-error-codes';

/**
 * The hosted-upload HTTP surface re-homed onto a REAL Postgres (#725): the raw
 * octet-stream body buffered to a Buffer, the empty-body/auth pipes, the real
 * quota/pin-fault faults mapping to their statuses, and the absolute size cap +
 * its pre-buffer auth gate. The upload runs the REAL ContentService against real
 * `users`/`pinned_cids` rows with a deterministic in-memory pin store, so the
 * quota gate and the 413/503 mapping are proven end-to-end, not stubbed.
 */

const GIB = 1024 * 1024 * 1024;

/** Deterministic CID from bytes so hash() and pin() always agree; records effects. */
class FakePinStore extends PinStore {
  readonly pinned: string[] = [];
  readonly unpinned: string[] = [];
  failPin = false;

  cidFor(bytes: Uint8Array): string {
    return `ba${createHash('sha256').update(bytes).digest('hex')}`;
  }
  override async hash(bytes: Uint8Array): Promise<string> {
    return this.cidFor(bytes);
  }
  override async pin(bytes: Uint8Array): Promise<string> {
    if (this.failPin) {
      throw new Error('pin store unavailable');
    }
    const cid = this.cidFor(bytes);
    this.pinned.push(cid);
    return cid;
  }
  async unpin(cid: string): Promise<boolean> {
    this.unpinned.push(cid);
    return true;
  }
}

describe('content HTTP (real Postgres)', () => {
  let db: IntegrationDatabase;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
  });

  afterAll(async () => {
    await db?.teardown();
  });

  describe('upload surface', () => {
    let ctx: HttpIntegrationApp;
    let jwt: JwtService;
    let pinStore: FakePinStore;

    beforeAll(async () => {
      pinStore = new FakePinStore();
      ctx = await createHttpIntegrationApp({
        db,
        entities: [User, PinnedCid],
        controllers: [ContentController],
        providers: [
          ContentService,
          JwtAuthGuard,
          { provide: PinStore, useValue: pinStore },
          {
            provide: ConfigService,
            useValue: fakeConfig({
              QUOTA_DEFAULT_BYTES: String(10 * GIB),
              DB_ADVISORY_LOCK_TIMEOUT_MS: '0',
            }).service,
          },
        ],
      });
      jwt = ctx.app.get(JwtService);
    });

    afterAll(async () => {
      await ctx?.close();
    });

    afterEach(async () => {
      pinStore.failPin = false;
      pinStore.pinned.length = 0;
      pinStore.unpinned.length = 0;
      await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    });

    /** Seed a hosted account and mint a valid access token for it. */
    async function account(overrides: Partial<User> = {}): Promise<{ id: string; token: string }> {
      const { userId, token } = await seedAccount(db, jwt, overrides);
      return { id: userId, token };
    }

    function post(token: string) {
      return request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream');
    }

    it('buffers the raw octet-stream body and durably pins it, returning the DTO', async () => {
      const acct = await account();
      const bytes = Buffer.from([1, 2, 3, 4, 5]);
      const res = await post(acct.token).send(bytes).expect(201);
      expect(res.body).toEqual({ cid: pinStore.cidFor(bytes), size: 5 });
      // The body reached the service as bytes and was durably pinned.
      expect(pinStore.pinned).toEqual([pinStore.cidFor(bytes)]);
      const rows = await db.dataSource
        .getRepository(PinnedCid)
        .find({ where: { accountId: acct.id } });
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid: pinStore.cidFor(bytes), size: '5' });
    });

    it('buffers a mixed-case Application/Octet-Stream content-type (case-insensitive per RFC 9110)', async () => {
      const acct = await account();
      const bytes = Buffer.from([7, 8]);
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${acct.token}`)
        .set('Content-Type', 'Application/Octet-Stream')
        .send(bytes)
        .expect(201);
      expect(res.body).toEqual({ cid: pinStore.cidFor(bytes), size: 2 });
      expect(pinStore.pinned).toEqual([pinStore.cidFor(bytes)]);
    });

    it('rejects an empty body with 400 before the service pins anything', async () => {
      const acct = await account();
      await post(acct.token).send(Buffer.alloc(0)).expect(400);
      expect(pinStore.pinned).toEqual([]);
    });

    it('rejects a request with no access token (401)', async () => {
      await request(ctx.http)
        .post('/content/upload')
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.from([9]))
        .expect(401);
      expect(pinStore.pinned).toEqual([]);
    });

    it('maps an over-quota upload to 413 discriminated by code QUOTA_EXCEEDED', async () => {
      const acct = await account({ quotaLimitOverride: '100' });
      await db.dataSource
        .getRepository(PinnedCid)
        .save({ accountId: acct.id, cid: 'baExisting', size: '60', advisory: false });
      // 60 already used + 60 incoming > 100.
      const res = await post(acct.token).send(Buffer.alloc(60, 1)).expect(413);
      expect(res.body).toMatchObject({
        statusCode: 413,
        error: 'Payload Too Large',
        code: QUOTA_EXCEEDED,
      });
      expect(pinStore.pinned).toEqual([]);
    });

    it('maps a pin-store fault to a retryable 503', async () => {
      const acct = await account();
      pinStore.failPin = true;
      await post(acct.token)
        .send(Buffer.from([1, 2, 3]))
        .expect(503);
      // The failed pin was compensated away — the account is charged nothing.
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { accountId: acct.id } })
      ).toHaveLength(0);
    });
  });

  describe('upload cap and pre-buffer auth gate', () => {
    const MAX = 16;
    let ctx: HttpIntegrationApp;
    let jwt: JwtService;
    let priorMax: string | undefined;

    beforeAll(async () => {
      priorMax = process.env.MAX_UPLOAD_BYTES;
      process.env.MAX_UPLOAD_BYTES = String(MAX);
      ctx = await createHttpIntegrationApp({
        db,
        entities: [User, PinnedCid],
        controllers: [ContentController],
        providers: [
          ContentService,
          JwtAuthGuard,
          { provide: PinStore, useValue: new FakePinStore() },
          {
            provide: ConfigService,
            useValue: fakeConfig({
              QUOTA_DEFAULT_BYTES: String(10 * GIB),
              DB_ADVISORY_LOCK_TIMEOUT_MS: '0',
            }).service,
          },
        ],
      });
      jwt = ctx.app.get(JwtService);
    });

    afterAll(async () => {
      await ctx?.close();
      if (priorMax === undefined) delete process.env.MAX_UPLOAD_BYTES;
      else process.env.MAX_UPLOAD_BYTES = priorMax;
    });

    afterEach(async () => {
      await db.dataSource.query('TRUNCATE TABLE users CASCADE');
    });

    async function authToken(expiresIn = 900): Promise<string> {
      const publicKey = randomCompressedPublicKey();
      const user = await db.dataSource.getRepository(User).save({ publicKey, byo: false });
      return jwt.signAsync({ sub: user.id, publicKey }, { expiresIn });
    }

    it('answers an over-cap authenticated upload with a real 413 JSON body discriminated by code UPLOAD_TOO_LARGE', async () => {
      const token = await authToken();
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.alloc(MAX + 8, 1))
        .expect(413);
      expect(res.body).toMatchObject({
        statusCode: 413,
        error: 'Payload Too Large',
        code: UPLOAD_TOO_LARGE,
      });
    });

    it('refuses an over-cap UNAUTHENTICATED upload with 401 before buffering (not 413)', async () => {
      await request(ctx.http)
        .post('/content/upload')
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.alloc(MAX + 8, 1))
        .expect(401);
    });

    it('refuses an over-cap EXPIRED-but-signed upload with 401 before buffering (not 413)', async () => {
      const expired = await authToken(-10);
      await request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${expired}`)
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.alloc(MAX + 8, 1))
        .expect(401);
    });

    it('still buffers and uploads for an unexpired valid token', async () => {
      const token = await authToken();
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.from([1, 2, 3]))
        .expect(201);
      expect(res.body).toMatchObject({ size: 3 });
    });
  });
});
