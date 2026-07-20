import { INestApplication } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { configureApp } from '../app-setup';
import { AuthController } from '../auth/auth.controller';
import { AuthService } from '../auth/services/auth.service';
import { TestAuthService } from '../auth/services/test-auth.service';
import { TokenService } from '../auth/services/token.service';
import { JwtService } from '@nestjs/jwt';
import { OpsModule } from './ops.module';
import { THROTTLE_SURFACES } from './throttling';

/**
 * The throttler must be EFFECTIVE, not decorative (v1's inert @Throttle is
 * a named defect — blueprint/api.md Ops). These specs drive real 429s
 * through the HTTP layer: the global APP_GUARD enforces the per-surface
 * @Throttle limits and honors @SkipThrottle on health/metrics.
 *
 * Handler internals are irrelevant here (the guard rejects before the
 * handler runs), so auth services are inert stubs.
 */
describe('ops HTTP surface', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;

  beforeAll(async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [ConfigModule.forRoot({ isGlobal: true, ignoreEnvFile: true }), OpsModule],
      controllers: [AuthController],
      providers: [
        { provide: AuthService, useValue: {} },
        { provide: TestAuthService, useValue: {} },
        { provide: TokenService, useValue: {} },
        { provide: JwtService, useValue: {} },
        { provide: ConfigService, useValue: { get: () => undefined } },
      ],
    }).compile();

    app = configureApp(moduleRef.createNestApplication());
    await app.init();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('global throttler with per-surface limits', () => {
    it('returns real 429s on the auth surface once its limit is exhausted', async () => {
      const limit = THROTTLE_SURFACES.auth.default.limit;
      // Invalid bodies on purpose: the guard runs before validation, so
      // within the limit we see 400s, and past it the guard's 429.
      for (let i = 0; i < limit; i += 1) {
        await request(http).post('/auth/challenge').send({}).expect(400);
      }
      const throttled = await request(http).post('/auth/challenge').send({}).expect(429);
      expect(throttled.headers['retry-after']).toBeDefined();
    });

    it('tracks surfaces independently: refresh still answers after auth is throttled', async () => {
      await request(http).post('/auth/challenge').send({}).expect(429);
      // 401 (missing token), not 429 — the refresh surface has its own bucket.
      await request(http).post('/auth/refresh').send({}).expect(401);
    });

    it('exempts health and metrics via SkipThrottle', async () => {
      const beyondLimit = THROTTLE_SURFACES.auth.default.limit + 5;
      for (let i = 0; i < beyondLimit; i += 1) {
        await request(http).get('/health').expect(200);
      }
      await request(http).get('/metrics').expect(200);
    });
  });

  describe('health stub and Prometheus metrics', () => {
    it('serves the health stub', async () => {
      const res = await request(http).get('/health').expect(200);
      expect(res.body).toEqual({ status: 'ok' });
    });

    it('exposes default process metrics and HTTP counters in Prometheus text format', async () => {
      await request(http).get('/health').expect(200);
      const res = await request(http).get('/metrics').expect(200);
      expect(res.headers['content-type']).toContain('text/plain');
      expect(res.text).toContain('process_cpu_user_seconds_total');
      expect(res.text).toContain('nodejs_eventloop_lag_seconds');
      expect(res.text).toContain('http_requests_total');
      expect(res.text).toMatch(/http_requests_total\{[^}]*route="\/health"[^}]*\} \d+/);
      expect(res.text).toContain('http_request_duration_seconds_bucket');
    });
  });
});
