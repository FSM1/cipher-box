import { INestApplication } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { secp256k1 } from '@noble/curves/secp256k1';
import { randomUUID } from 'node:crypto';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OpsModule } from '../ops/ops.module';
import { THROTTLE_SURFACES } from '../ops/throttling';
import { RecoveryController } from './recovery.controller';
import { RecordCacheService } from './services/record-cache.service';

const SECRET = 'recovery-test-secret';

/** Collect a binary response body for byte-exact assertions. */
function binaryParser(res: request.Response, callback: (err: Error | null, body: Buffer) => void) {
  const chunks: Buffer[] = [];
  res.on('data', (chunk: Buffer) => chunks.push(Buffer.from(chunk)));
  res.on('end', () => callback(null, Buffer.concat(chunks)));
}

describe('recovery HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;
  const cache = new Map<string, Buffer>();

  const cacheService: Pick<RecordCacheService, 'fetch'> = {
    fetch: async (ipnsName: string) => cache.get(ipnsName) ?? null,
  };

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;
    jwt = new JwtService();

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        OpsModule,
        JwtModule.register({ secret: SECRET, signOptions: { expiresIn: 900 } }),
      ],
      controllers: [RecoveryController],
      providers: [JwtAuthGuard, { provide: RecordCacheService, useValue: cacheService }],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
    if (priorJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = priorJwtSecret;
  });

  async function token(): Promise<string> {
    const priv = secp256k1.utils.randomPrivateKey();
    const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
    return jwt.signAsync({ sub: randomUUID(), publicKey }, { secret: SECRET });
  }

  it('serves cached record bytes to an authenticated caller', async () => {
    const name = 'k51recoveryhappy';
    const bytes = Buffer.from([1, 2, 3, 4, 5, 250, 200]);
    cache.set(name, bytes);

    const res = await request(http)
      .get(`/recovery/${name}`)
      .set('Authorization', `Bearer ${await token()}`)
      .buffer(true)
      .parse(binaryParser)
      .expect(200);

    expect(res.headers['content-type']).toContain('application/vnd.ipfs.ipns-record');
    expect(Buffer.compare(res.body, bytes)).toBe(0);
  });

  it('returns 404 for a name that was never cached', async () => {
    await request(http)
      .get('/recovery/k51neverseen')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });

  it('returns 404 for a malformed name without faulting', async () => {
    await request(http)
      .get('/recovery/not%20a%20valid%20name')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });

  it('requires authentication', async () => {
    await request(http).get('/recovery/k51recoveryhappy').expect(401);
  });

  it('rate-limits the recovery surface per account (real 429s)', async () => {
    const authed = `Bearer ${await token()}`;
    const limit = THROTTLE_SURFACES.recovery.default.limit;
    for (let i = 0; i < limit; i += 1) {
      await request(http).get('/recovery/k51burst').set('Authorization', authed).expect(404);
    }
    const throttled = await request(http)
      .get('/recovery/k51burst')
      .set('Authorization', authed)
      .expect(429);
    expect(throttled.headers['retry-after']).toBeDefined();
  });

  it('keys the recovery limit by account: a fresh account is unaffected', async () => {
    await request(http)
      .get('/recovery/k51fresh')
      .set('Authorization', `Bearer ${await token()}`)
      .expect(404);
  });
});
