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
