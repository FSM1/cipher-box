import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { createHash } from 'node:crypto';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { PinnedCid } from '../registry/entities/pinned-cid.entity';
import { PinCidMismatchError, PinStore } from '../registry/pin-store';
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

/** Base32 alphabet of the CID's multibase, per `content-cid.ts`'s `CONTENT_CID_PATTERN`. */
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/** The CID prefix each content-plane codec takes, per `content-cid.ts`. */
const CODEC_PREFIX = { raw: 'bafkr4i', 'dag-cbor': 'bafyr4i' } as const;

class FakePinStore extends PinStore {
  readonly pinned: string[] = [];
  readonly unpinned: string[] = [];
  failPin = false;

  /**
   * Deterministic CID from bytes, shaped like a real content CID (7-char codec
   * prefix + 52 base32 chars = the 58-char body `contentCidCodec` requires) so
   * it survives the controller's shape check.
   */
  cidFor(bytes: Uint8Array, codec: keyof typeof CODEC_PREFIX = 'raw'): string {
    const hex = createHash('sha256').update(bytes).digest('hex');
    const suffix = hex
      .slice(0, 52)
      .split('')
      .map((nibble) => BASE32_ALPHABET[parseInt(nibble, 16)])
      .join('');
    return `${CODEC_PREFIX[codec]}${suffix}`;
  }
  override async pin(cid: string, bytes: Uint8Array): Promise<void> {
    if (this.failPin) {
      throw new Error('pin store unavailable');
    }
    // Kubo addresses the block under the declared CID's own codec, so the fake
    // reads the codec back off the declared address before comparing.
    const codec = cid.startsWith(CODEC_PREFIX['dag-cbor']) ? 'dag-cbor' : 'raw';
    const actual = this.cidFor(bytes, codec);
    if (actual !== cid) {
      throw new PinCidMismatchError(cid, actual);
    }
    this.pinned.push(cid);
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

    function post(token: string, cid: string) {
      return request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', cid)
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream');
    }

    it('buffers the raw octet-stream body and durably pins it, returning the DTO', async () => {
      const acct = await account();
      const bytes = Buffer.from([1, 2, 3, 4, 5]);
      const cid = pinStore.cidFor(bytes);
      const res = await post(acct.token, cid).send(bytes).expect(201);
      expect(res.body).toEqual({ cid, size: 5 });
      // The body reached the service as bytes and was durably pinned.
      expect(pinStore.pinned).toEqual([cid]);
      const rows = await db.dataSource
        .getRepository(PinnedCid)
        .find({ where: { accountId: acct.id } });
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({ cid, size: '5' });
    });

    it('buffers a mixed-case Application/Octet-Stream content-type (case-insensitive per RFC 9110)', async () => {
      const acct = await account();
      const bytes = Buffer.from([7, 8]);
      const cid = pinStore.cidFor(bytes);
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', cid)
        .set('Authorization', `Bearer ${acct.token}`)
        .set('Content-Type', 'Application/Octet-Stream')
        .send(bytes)
        .expect(201);
      expect(res.body).toEqual({ cid, size: 2 });
      expect(pinStore.pinned).toEqual([cid]);
    });

    it('accepts a dag-cbor-codec declared CID, pinning a DAG root under it', async () => {
      const acct = await account();
      const bytes = Buffer.from([0xa1, 0x61, 0x61, 0x01]);
      const cid = pinStore.cidFor(bytes, 'dag-cbor');
      const res = await post(acct.token, cid).send(bytes).expect(201);
      expect(res.body).toEqual({ cid, size: 4 });
      expect(pinStore.pinned).toEqual([cid]);
    });

    it('rejects an empty body with 400 before the service pins anything', async () => {
      const acct = await account();
      const cid = pinStore.cidFor(Buffer.alloc(0));
      await post(acct.token, cid).send(Buffer.alloc(0)).expect(400);
      expect(pinStore.pinned).toEqual([]);
    });

    it('rejects a request with no declared CID (400), reaching neither pin store', async () => {
      const acct = await account();
      await request(ctx.http)
        .post('/content/upload')
        .set('Authorization', `Bearer ${acct.token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.from([9]))
        .expect(400);
      expect(pinStore.pinned).toEqual([]);
    });

    it('rejects a request with a malformed cid (400), reaching neither pin store', async () => {
      const acct = await account();
      await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', 'not-a-cid')
        .set('Authorization', `Bearer ${acct.token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(Buffer.from([9]))
        .expect(400);
      expect(pinStore.pinned).toEqual([]);
    });

    it('rejects a request with no access token (401)', async () => {
      const cid = pinStore.cidFor(Buffer.from([9]));
      await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', cid)
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
      const bytes = Buffer.alloc(60, 1);
      const res = await post(acct.token, pinStore.cidFor(bytes)).send(bytes).expect(413);
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
      const bytes = Buffer.from([1, 2, 3]);
      await post(acct.token, pinStore.cidFor(bytes)).send(bytes).expect(503);
      // The failed pin was compensated away — the account is charged nothing.
      expect(
        await db.dataSource.getRepository(PinnedCid).find({ where: { accountId: acct.id } })
      ).toHaveLength(0);
    });

    it('maps a declared cid that does not address the bytes to a 400, compensating the charge', async () => {
      const acct = await account();
      const bytes = Buffer.from([4, 5, 6]);
      const wrongCid = pinStore.cidFor(Buffer.from([9, 9, 9]));
      await post(acct.token, wrongCid).send(bytes).expect(400);
      // Compensated, not just uncharged-on-failure: no row, nothing pinned.
      expect(pinStore.pinned).toEqual([]);
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
    let pinStore: FakePinStore;

    beforeAll(async () => {
      priorMax = process.env.MAX_UPLOAD_BYTES;
      process.env.MAX_UPLOAD_BYTES = String(MAX);
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
      const bytes = Buffer.alloc(MAX + 8, 1);
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', pinStore.cidFor(bytes))
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(bytes)
        .expect(413);
      expect(res.body).toMatchObject({
        statusCode: 413,
        error: 'Payload Too Large',
        code: UPLOAD_TOO_LARGE,
      });
    });

    it('refuses an over-cap UNAUTHENTICATED upload with 401 before buffering (not 413)', async () => {
      const bytes = Buffer.alloc(MAX + 8, 1);
      await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', pinStore.cidFor(bytes))
        .set('Content-Type', 'application/octet-stream')
        .send(bytes)
        .expect(401);
    });

    it('refuses an over-cap EXPIRED-but-signed upload with 401 before buffering (not 413)', async () => {
      const expired = await authToken(-10);
      const bytes = Buffer.alloc(MAX + 8, 1);
      await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', pinStore.cidFor(bytes))
        .set('Authorization', `Bearer ${expired}`)
        .set('Content-Type', 'application/octet-stream')
        .send(bytes)
        .expect(401);
    });

    it('still buffers and uploads for an unexpired valid token', async () => {
      const token = await authToken();
      const bytes = Buffer.from([1, 2, 3]);
      const res = await request(ctx.http)
        .post('/content/upload')
        .set('x-content-cid', pinStore.cidFor(bytes))
        .set('Authorization', `Bearer ${token}`)
        .set('Content-Type', 'application/octet-stream')
        .send(bytes)
        .expect(201);
      expect(res.body).toMatchObject({ size: 3 });
    });
  });
});
