import { ConfigService } from '@nestjs/config';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { AuthController } from '../auth/auth.controller';
import { AuthMethod } from '../auth/entities/auth-method.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuthService } from '../auth/services/auth.service';
import { ChallengeService } from '../auth/services/challenge.service';
import { IdentityService } from '../auth/services/identity.service';
import { SiweService } from '../auth/services/siwe.service';
import { TestAuthService } from '../auth/services/test-auth.service';
import { GatewayToken } from '../auth/entities/gateway-token.entity';
import { GatewayTokenService } from '../auth/services/gateway-token.service';
import { TokenService } from '../auth/services/token.service';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';
import { resolveAuthLimit } from './throttling';

/**
 * The Ops HTTP surface on a booted app against a throwaway Postgres: the
 * WORKING global throttler driving real per-surface 429s (v1's inert @Throttle
 * is a named defect), the @SkipThrottle exemptions for health/metrics, the
 * health stub, and the Prometheus text output. The real AuthController is
 * mounted so the throttler is proven on the actual auth/refresh surfaces; the
 * guard rejects before the handler, so the DB is untouched on these paths.
 */

describe('ops HTTP surface (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp;

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 10 });
    ctx = await createHttpIntegrationApp({
      db,
      entities: [User, AuthMethod, RefreshToken, GatewayToken],
      controllers: [AuthController],
      providers: [
        AuthService,
        TestAuthService,
        TokenService,
        GatewayTokenService,
        ChallengeService,
        IdentityService,
        SiweService,
        JwtAuthGuard,
        { provide: Clock, useClass: SystemClock },
        { provide: Entropy, useClass: SystemEntropy },
        { provide: ConfigService, useValue: fakeConfig({ NODE_ENV: 'test' }).service },
      ],
    });
  });

  afterAll(async () => {
    await ctx?.close();
    await db?.teardown();
  });

  const http = () => ctx.http;

  describe('global throttler with per-surface limits', () => {
    it('returns real 429s on the auth surface once its limit is exhausted', async () => {
      const limit = resolveAuthLimit();
      // Invalid bodies on purpose: the guard runs before validation, so within
      // the limit we see 400s, and past it the guard's 429.
      for (let i = 0; i < limit; i += 1) {
        await request(http()).post('/auth/challenge').send({}).expect(400);
      }
      const throttled = await request(http()).post('/auth/challenge').send({}).expect(429);
      expect(throttled.headers['retry-after']).toBeDefined();
    });

    it('tracks surfaces independently: refresh still answers after auth is throttled', async () => {
      await request(http()).post('/auth/challenge').send({}).expect(429);
      // 401 (missing token), not 429 — the refresh surface has its own bucket.
      await request(http()).post('/auth/refresh').send({}).expect(401);
    });

    it('exempts health and metrics via SkipThrottle', async () => {
      const beyondLimit = resolveAuthLimit() + 5;
      for (let i = 0; i < beyondLimit; i += 1) {
        await request(http()).get('/health').expect(200);
      }
      await request(http()).get('/metrics').expect(200);
    });
  });

  describe('health stub and Prometheus metrics', () => {
    it('serves the health stub', async () => {
      const res = await request(http()).get('/health').expect(200);
      expect(res.body).toEqual({ status: 'ok' });
    });

    it('exposes default process metrics and HTTP counters in Prometheus text format', async () => {
      await request(http()).get('/health').expect(200);
      const res = await request(http()).get('/metrics').expect(200);
      expect(res.headers['content-type']).toContain('text/plain');
      expect(res.text).toContain('process_cpu_user_seconds_total');
      expect(res.text).toContain('nodejs_eventloop_lag_seconds');
      expect(res.text).toContain('http_requests_total');
      expect(res.text).toMatch(/http_requests_total\{[^}]*route="\/health"[^}]*\} \d+/);
      expect(res.text).toContain('http_request_duration_seconds_bucket');
    });
  });
});
