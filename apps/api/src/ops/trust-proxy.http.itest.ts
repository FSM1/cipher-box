import { ConfigService } from '@nestjs/config';
import request from 'supertest';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { AuthMetricsInterceptor } from '../auth/auth-metrics.interceptor';
import { AuthController } from '../auth/auth.controller';
import { AuthMethod } from '../auth/entities/auth-method.entity';
import { GatewayToken } from '../auth/entities/gateway-token.entity';
import { RefreshToken } from '../auth/entities/refresh-token.entity';
import { User } from '../auth/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { AuthService } from '../auth/services/auth.service';
import { ChallengeService } from '../auth/services/challenge.service';
import { GatewayTokenService } from '../auth/services/gateway-token.service';
import { IdentityService } from '../auth/services/identity.service';
import { SiweService } from '../auth/services/siwe.service';
import { TestAuthService } from '../auth/services/test-auth.service';
import { TokenService } from '../auth/services/token.service';
import { Clock, SystemClock } from '../common/clock';
import { Entropy, SystemEntropy } from '../common/entropy';
import { fakeConfig } from '../testing/fakes';
import { createHttpIntegrationApp, HttpIntegrationApp } from '../testing/http-integration-app';
import { createIntegrationDatabase, IntegrationDatabase } from '../testing/integration-db';

/**
 * Every IP-keyed limit reads `req.ip`. Behind a reverse proxy that is the
 * proxy's own address, so without `TRUST_PROXY_HOPS` the whole internet shares
 * one bucket and the auth cap becomes a global availability limit instead of a
 * per-attacker one.
 *
 * The forwarded address is also counted from the RIGHT of `X-Forwarded-For`: an
 * entry a client injects lands left of the hop count, so it must not become the
 * key. Driven through `/auth/challenge` with invalid bodies — the guard runs
 * before validation, so within the cap the answer is 400 and past it 429.
 */
describe('trust-proxy client-address resolution (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp | undefined;
  const originalEnv = { ...process.env };

  /** A cap low enough that one forwarded address exhausts it in a short burst. */
  const CAP = 4;
  const CLIENT = '198.51.100.7';
  const OTHER_CLIENT = '203.0.113.9';

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 5 });
  });

  afterEach(async () => {
    await ctx?.close();
    ctx = undefined;
    process.env = { ...originalEnv };
  });

  afterAll(async () => {
    await db?.teardown();
  });

  async function boot(hops: string | undefined): Promise<HttpIntegrationApp> {
    process.env.THROTTLE_AUTH_LIMIT = String(CAP);
    if (hops === undefined) {
      delete process.env.TRUST_PROXY_HOPS;
    } else {
      process.env.TRUST_PROXY_HOPS = hops;
    }
    ctx = await createHttpIntegrationApp({
      db,
      entities: [User, AuthMethod, RefreshToken, GatewayToken],
      controllers: [AuthController],
      providers: [
        AuthMetricsInterceptor,
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
    return ctx;
  }

  function challenge(app: HttpIntegrationApp, forwardedFor: string) {
    return request(app.http).post('/auth/challenge').set('X-Forwarded-For', forwardedFor).send({});
  }

  /** Spend one forwarded address's whole budget; return the status past the cap. */
  async function exhaust(app: HttpIntegrationApp, forwardedFor: string): Promise<number> {
    for (let i = 0; i < CAP; i += 1) {
      await challenge(app, forwardedFor);
    }
    return (await challenge(app, forwardedFor)).status;
  }

  it('collapses every forwarded client into one bucket when unconfigured', async () => {
    const app = await boot(undefined);
    expect(await exhaust(app, CLIENT)).toBe(429);
    // A second client, refused on traffic it never sent.
    expect((await challenge(app, OTHER_CLIENT)).status).toBe(429);
  });

  it('gives each forwarded client its own bucket at one hop', async () => {
    const app = await boot('1');
    expect(await exhaust(app, CLIENT)).toBe(429);
    expect((await challenge(app, OTHER_CLIENT)).status).toBe(400);
  });

  it('keys on the hop-counted address, not a client-injected one', async () => {
    const app = await boot('1');
    expect(await exhaust(app, CLIENT)).toBe(429);
    // Prepending an invented entry pushes the real address right of it; the hop
    // count still lands on the real one, so the bucket is not escaped.
    expect((await challenge(app, `192.0.2.1, ${CLIENT}`)).status).toBe(429);
  });
});
