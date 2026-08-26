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
 * `TRUST_PROXY_HOPS` is what makes every IP-keyed limit per-attacker rather than
 * global; see .env.example for how to size it. Driven through `/auth/challenge`
 * with invalid bodies, since the guard runs before validation: within the cap
 * the answer is 400, past it 429.
 */
describe('trust-proxy client-address resolution (real Postgres)', () => {
  let db: IntegrationDatabase;
  let ctx: HttpIntegrationApp | undefined;

  /** A cap low enough that one forwarded address exhausts it in a short burst. */
  const CAP = 4;
  const CLIENT = '198.51.100.7';
  const OTHER_CLIENT = '203.0.113.9';
  /** An entry no proxy wrote — whatever the caller chose to prepend. */
  const SPOOF = '192.0.2.44';
  /** The Cloudflare edge Caddy appends once it trusts the ranges in front. */
  const EDGE = '162.158.0.1';

  beforeAll(async () => {
    db = await createIntegrationDatabase({ poolMax: 5 });
  });

  afterEach(async () => {
    await ctx?.close();
    ctx = undefined;
    delete process.env.TRUST_PROXY_HOPS;
    delete process.env.THROTTLE_AUTH_LIMIT;
  });

  afterAll(async () => {
    await db?.teardown();
  });

  async function boot(hops: string | undefined): Promise<HttpIntegrationApp> {
    process.env.THROTTLE_AUTH_LIMIT = String(CAP);
    if (hops !== undefined) {
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

  it('keys each forwarded client separately at one hop', async () => {
    const app = await boot('1');
    expect(await exhaust(app, CLIENT)).toBe(429);
    expect((await challenge(app, OTHER_CLIENT)).status).toBe(400);
    // Prepending an invented entry pushes the real address right of it; the hop
    // count still lands on the real one, so the bucket is not escaped.
    expect((await challenge(app, `192.0.2.1, ${CLIENT}`)).status).toBe(429);
  });

  /**
   * The direction that fails OPEN, pinned so raising the count stays a decision
   * rather than a default. One hop past the real chain and Express runs off the
   * end of `X-Forwarded-For` onto the leftmost entry, which the client writes —
   * so the caller, not the deployment, picks its own rate-limit bucket.
   */
  it('lets a client pick its own bucket when the hop count overshoots the chain', async () => {
    const app = await boot('2');
    expect(await exhaust(app, `${SPOOF}, ${CLIENT}`)).toBe(429);
    // Same real client, a different invented entry: a fresh budget.
    expect((await challenge(app, `198.18.0.1, ${CLIENT}`)).status).toBe(400);
  });

  /** The staging chain: Cloudflare appends the member, Caddy appends the edge. */
  it('resolves the member behind Cloudflare and Caddy at two hops', async () => {
    const app = await boot('2');
    expect(await exhaust(app, `${CLIENT}, ${EDGE}`)).toBe(429);
    // Counting from the peer, a prepended entry stays left of the member: the
    // two rightmost are both proxy-written, so the bucket cannot be escaped.
    expect((await challenge(app, `${SPOOF}, ${CLIENT}, ${EDGE}`)).status).toBe(429);
    expect((await challenge(app, `${OTHER_CLIENT}, ${EDGE}`)).status).toBe(400);
  });

  /** What the count was before Caddy trusted Cloudflare, and why it moved. */
  it('collapses a whole Cloudflare edge into one bucket at one hop', async () => {
    const app = await boot('1');
    expect(await exhaust(app, `${CLIENT}, ${EDGE}`)).toBe(429);
    expect((await challenge(app, `${OTHER_CLIENT}, ${EDGE}`)).status).toBe(429);
  });
});
