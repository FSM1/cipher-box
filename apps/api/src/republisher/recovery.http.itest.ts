import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { THROTTLE_SURFACES } from '../ops/throttling';
import {
  createHttpIntegrationApp,
  HttpIntegrationApp,
  randomCompressedPublicKey,
} from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { RecordCache } from './entities/record-cache.entity';
import { RecoveryController } from './recovery.controller';
import { RecordCacheService } from './services/record-cache.service';

/**
 * The recovery HTTP surface re-homed onto a REAL Postgres: the real
 * RecordCacheService serving cached record bytes from a real `record_cache` row,
 * the absent/malformed-name 404s, the auth guard, and the real per-account 429s.
 * The cache lookup is genuine SQL against the varchar-keyed table, so the
 * malformed-name path is proven not to fault the query.
 */

const IPNS_RECORD_MEDIA_TYPE = 'application/vnd.ipfs.ipns-record';

/** Collect a binary response body for byte-exact assertions. */
function binaryParser(res: request.Response, callback: (err: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = [];
  res.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

describe('recovery HTTP surface (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;
  let jwt: JwtService;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    ctx = await createHttpIntegrationApp({
      db,
      entities: [RecordCache],
      controllers: [RecoveryController],
      providers: [RecordCacheService, JwtAuthGuard],
    });
    jwt = ctx.app.get(JwtService);
  });

  afterAll(async () => {
    await ctx?.close();
    await db?.teardown();
  });

  beforeEach(async () => {
    await db.dataSource.query('TRUNCATE TABLE record_cache');
  });

  const http = () => ctx.http;

  /** A valid access token; recovery is stateless w.r.t. the users table. */
  async function token(): Promise<string> {
    return jwt.signAsync({ sub: randomUUID(), publicKey: randomCompressedPublicKey() });
  }

  async function seedCache(ipnsName: string, record: Buffer): Promise<void> {
    await db.dataSource
      .getRepository(RecordCache)
      .save({ ipnsName, record, sequence: '1', lastRepublishedAt: null });
  }

  it('serves cached record bytes to an authenticated caller', async () => {
    const name = 'k51recoveryhappy';
    const bytes = Buffer.from([1, 2, 3, 4, 5, 250, 200]);
    await seedCache(name, bytes);

    const res = await request(http())
      .get(`/recovery/${name}`)
      .set('Authorization', `Bearer ${await token()}`)
      .buffer(true)
      .parse(binaryParser)
      .expect(200);

    expect(res.headers['content-type']).toContain(IPNS_RECORD_MEDIA_TYPE);
    expect(Buffer.compare(res.body, bytes)).toBe(0);
  });

  it('returns 404 for a name that was never cached', async () => {
    await request(http())
      .get('/recovery/k51neverseen')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });

  it('returns 404 for a malformed name without faulting', async () => {
    await request(http())
      .get('/recovery/not%20a%20valid%20name')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });

  it('requires authentication', async () => {
    await request(http()).get('/recovery/k51recoveryhappy').expect(401);
  });

  it('rate-limits the recovery surface per account (real 429s)', async () => {
    const authed = `Bearer ${await token()}`;
    const limit = THROTTLE_SURFACES.recovery.default.limit;
    for (let i = 0; i < limit; i += 1) {
      await request(http()).get('/recovery/k51burst').set('Authorization', authed).expect(404);
    }
    const throttled = await request(http())
      .get('/recovery/k51burst')
      .set('Authorization', authed)
      .expect(429);
    expect(throttled.headers['retry-after']).toBeDefined();
  });

  it('keys the recovery limit by account: a fresh account is unaffected', async () => {
    await request(http())
      .get('/recovery/k51fresh')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });
});
