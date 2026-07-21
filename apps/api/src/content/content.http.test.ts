import {
  INestApplication,
  PayloadTooLargeException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule, JwtService } from '@nestjs/jwt';
import { Test } from '@nestjs/testing';
import { secp256k1 } from '@noble/curves/secp256k1';
import request from 'supertest';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { OpsModule } from '../ops/ops.module';
import { configureApp } from '../app-setup';
import { ContentController } from './content.controller';
import { ContentService, UploadResult } from './content.service';

const SECRET = 'content-test-secret';

/**
 * The hosted-upload endpoint's HTTP behavior with the service mocked: the raw
 * octet-stream body reaches the service as a Buffer, the DTO round-trips, auth
 * is enforced, an empty body is rejected before the service runs, and a
 * service-raised quota/pin fault maps to its status. The gate arithmetic and
 * concurrency live in the real-Postgres integration suite.
 */
describe('content HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let jwt: JwtService;
  let upload: ReturnType<typeof vi.fn>;
  let priorJwtSecret: string | undefined;

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    process.env.JWT_SECRET = SECRET;
    upload = vi.fn();
    jwt = new JwtService();

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        OpsModule,
        JwtModule.register({ secret: SECRET, signOptions: { expiresIn: 900 } }),
      ],
      controllers: [ContentController],
      providers: [JwtAuthGuard, { provide: ContentService, useValue: { upload } }],
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

  beforeEach(() => {
    upload.mockReset();
  });

  async function token(): Promise<{ userId: string; token: string }> {
    const priv = secp256k1.utils.randomPrivateKey();
    try {
      const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
      const userId = '11111111-1111-4111-8111-111111111111';
      return { userId, token: await jwt.signAsync({ sub: userId, publicKey }, { secret: SECRET }) };
    } finally {
      priv.fill(0);
    }
  }

  function post(t: string) {
    return request(http)
      .post('/content/upload')
      .set('Authorization', `Bearer ${t}`)
      .set('Content-Type', 'application/octet-stream');
  }

  it('passes the raw octet-stream body to the service as a Buffer and returns the DTO', async () => {
    const auth = await token();
    const result: UploadResult = { cid: 'bafyUploaded', size: 5 };
    upload.mockResolvedValue(result);

    const res = await post(auth.token)
      .send(Buffer.from([1, 2, 3, 4, 5]))
      .expect(201);

    expect(res.body).toEqual(result);
    expect(upload).toHaveBeenCalledTimes(1);
    const [accountArg, bytesArg] = upload.mock.calls[0];
    expect(accountArg).toBe(auth.userId);
    expect(Buffer.isBuffer(bytesArg)).toBe(true);
    expect([...(bytesArg as Buffer)]).toEqual([1, 2, 3, 4, 5]);
  });

  it('buffers a mixed-case Application/Octet-Stream content-type (case-insensitive per RFC 9110)', async () => {
    const auth = await token();
    const result: UploadResult = { cid: 'bafyMixedCase', size: 2 };
    upload.mockResolvedValue(result);

    const res = await request(http)
      .post('/content/upload')
      .set('Authorization', `Bearer ${auth.token}`)
      .set('Content-Type', 'Application/Octet-Stream')
      .send(Buffer.from([7, 8]))
      .expect(201);

    expect(res.body).toEqual(result);
    const [, bytesArg] = upload.mock.calls[0];
    expect([...(bytesArg as Buffer)]).toEqual([7, 8]);
  });

  it('rejects an empty body with 400 before the service runs', async () => {
    const auth = await token();
    await post(auth.token).send(Buffer.alloc(0)).expect(400);
    expect(upload).not.toHaveBeenCalled();
  });

  it('rejects a request with no access token (401)', async () => {
    await request(http)
      .post('/content/upload')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from([9]))
      .expect(401);
    expect(upload).not.toHaveBeenCalled();
  });

  it('maps an over-quota service fault to 413', async () => {
    const auth = await token();
    upload.mockRejectedValue(
      new PayloadTooLargeException('Upload exceeds the account storage quota')
    );
    await post(auth.token)
      .send(Buffer.from([1, 2, 3]))
      .expect(413);
  });

  it('maps a pin-store fault to a retryable 503', async () => {
    const auth = await token();
    upload.mockRejectedValue(
      new ServiceUnavailableException('Pin store unavailable; upload not durable')
    );
    await post(auth.token)
      .send(Buffer.from([1, 2, 3]))
      .expect(503);
  });
});

/**
 * The raw-body cap and its auth gate, with a low MAX_UPLOAD_BYTES so the cap is
 * cheap to trip. Proves (a) an over-cap authenticated upload gets a real 413 JSON
 * response — not a connection reset from destroying the socket — and (b) an
 * UNAUTHENTICATED over-cap upload is refused with 401 BEFORE any buffering, so a
 * credential-less client cannot force the process to buffer up to the cap.
 */
describe('content upload cap and pre-buffer auth gate', () => {
  const MAX = 16;
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let jwt: JwtService;
  let priorJwtSecret: string | undefined;
  let priorMax: string | undefined;

  beforeAll(async () => {
    priorJwtSecret = process.env.JWT_SECRET;
    priorMax = process.env.MAX_UPLOAD_BYTES;
    process.env.JWT_SECRET = SECRET;
    process.env.MAX_UPLOAD_BYTES = String(MAX);
    jwt = new JwtService();

    const moduleRef = await Test.createTestingModule({
      imports: [
        ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }),
        OpsModule,
        JwtModule.register({ secret: SECRET, signOptions: { expiresIn: 900 } }),
      ],
      controllers: [ContentController],
      providers: [JwtAuthGuard, { provide: ContentService, useValue: { upload: vi.fn() } }],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
    if (priorJwtSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = priorJwtSecret;
    if (priorMax === undefined) delete process.env.MAX_UPLOAD_BYTES;
    else process.env.MAX_UPLOAD_BYTES = priorMax;
  });

  async function authToken(expiresIn = 900): Promise<string> {
    const priv = secp256k1.utils.randomPrivateKey();
    try {
      const publicKey = Buffer.from(secp256k1.getPublicKey(priv, true)).toString('hex');
      return jwt.signAsync(
        { sub: '11111111-1111-4111-8111-111111111111', publicKey },
        { secret: SECRET, expiresIn }
      );
    } finally {
      priv.fill(0);
    }
  }

  it('answers an over-cap authenticated upload with a real 413 JSON body (no connection reset)', async () => {
    const token = await authToken();
    const res = await request(http)
      .post('/content/upload')
      .set('Authorization', `Bearer ${token}`)
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.alloc(MAX + 8, 1))
      .expect(413);
    expect(res.body).toMatchObject({ statusCode: 413, error: 'Payload Too Large' });
  });

  it('refuses an over-cap UNAUTHENTICATED upload with 401 before buffering (not 413)', async () => {
    await request(http)
      .post('/content/upload')
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.alloc(MAX + 8, 1))
      .expect(401);
  });

  it('refuses an over-cap EXPIRED-but-signed upload with 401 before buffering (not 413)', async () => {
    // A genuine signature over an expired `exp`: it must NOT trigger buffering,
    // so the over-cap body is rejected as 401 (unbuffered), never 413.
    const expired = await authToken(-10);
    await request(http)
      .post('/content/upload')
      .set('Authorization', `Bearer ${expired}`)
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.alloc(MAX + 8, 1))
      .expect(401);
  });

  it('still buffers and uploads for an unexpired valid token', async () => {
    const token = await authToken();
    const res = await request(http)
      .post('/content/upload')
      .set('Authorization', `Bearer ${token}`)
      .set('Content-Type', 'application/octet-stream')
      .send(Buffer.from([1, 2, 3]))
      .expect(201);
    expect(res.body).toBeDefined();
  });
});
