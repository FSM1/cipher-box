import { ExecutionContext, Inject, Injectable } from '@nestjs/common';
import { ThrottlerGuard, ThrottlerLimitDetail } from '@nestjs/throttler';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { MetricsService } from './metrics.service';
import { routeLabelFor } from './route-label';

/**
 * Global throttler keyed by the authenticated account when the bearer carries
 * a VERIFIED access token, falling back to the client IP otherwise.
 *
 * The blueprint's mailbox limits are per SENDER account (post) and per
 * RECIPIENT mailbox (poll/ack) — both the authenticated account — so the
 * tracker must be the account, not the IP. Buckets are already separated per
 * route+throttler by the base `generateKey`, so this only widens the tracker.
 *
 * Why the signature is checked here even though it is only a rate-limit key,
 * not an authorization decision: this guard is a global `APP_GUARD`, so it runs
 * BEFORE the route's `JwtAuthGuard`, and `@nestjs/throttler` increments the
 * bucket before it would reject. Trusting an UNVERIFIED `sub` would therefore
 * let a forged, never-authenticated token (i) poison another account's bucket
 * (counting toward the victim's limit before the 401) and (ii) mint unbounded
 * distinct tracker keys from a single source — worse than the IP tracker it
 * replaces. Requiring our own HS256 signature closes both: a token we did not
 * sign falls back to the IP tracker. (Confidentiality was never at risk — the
 * route's `JwtAuthGuard` still rejects any unsigned/invalid token with 401, so
 * a forged `sub` can neither store a message nor reach the existence oracle.)
 * Unauthenticated routes carry no bearer and keep the base IP tracker.
 */
@Injectable()
export class AccountThrottlerGuard extends ThrottlerGuard {
  // Not a ctor param: re-declaring ThrottlerGuard's own parameters would pin
  // this guard to them.
  @Inject(MetricsService) private readonly metricsService: MetricsService;

  protected async getTracker(req: Record<string, unknown>): Promise<string> {
    const subject = verifiedSubjectFromBearer(req.headers as Record<string, unknown> | undefined);
    if (subject) {
      return `acct:${subject}`;
    }
    return super.getTracker(req);
  }

  /**
   * A guard runs before every interceptor, so a 429 never reaches
   * `MetricsInterceptor` and has no `http_requests_total` sample.
   */
  protected async throwThrottlingException(
    context: ExecutionContext,
    detail: ThrottlerLimitDetail
  ): Promise<void> {
    this.metricsService.observeThrottleRejection(routeLabelFor(context));
    return super.throwThrottlingException(context, detail);
  }
}

/** The effective HS256 secret, resolved exactly as `buildJwtOptions` does. */
function jwtSecret(): string {
  return process.env.JWT_SECRET ?? 'cipherbox-dev-jwt-secret';
}

/**
 * The signature-verified claims of a bearer token, or `undefined` when the
 * header is absent/malformed or carries a signature we did not produce. The
 * declared `alg` is never trusted — the signature is always recomputed as
 * HMAC-SHA256, so `alg: none`/algorithm-confusion cannot forge claims.
 */
function verifiedBearerClaims(
  headers: Record<string, unknown> | undefined
): { sub?: unknown; exp?: unknown } | undefined {
  const authorization = headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return undefined;
  }
  const parts = authorization.slice('Bearer '.length).split('.');
  if (parts.length !== 3) {
    return undefined;
  }
  const [header, payload, signature] = parts;
  const expected = createHmac('sha256', jwtSecret()).update(`${header}.${payload}`).digest();
  let provided: Buffer;
  try {
    provided = Buffer.from(signature, 'base64url');
  } catch {
    return undefined;
  }
  if (provided.length !== expected.length || !timingSafeEqual(provided, expected)) {
    return undefined;
  }
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as {
      sub?: unknown;
      exp?: unknown;
    };
  } catch {
    return undefined;
  }
}

/**
 * Return the `sub` claim ONLY when the bearer carries our own HS256 signature;
 * otherwise `undefined` (so the caller keys by IP). Expiry is intentionally not
 * enforced: a validly-signed-but-expired token still carries a genuine (non-
 * forgeable) `sub`, which is a correct rate-limit key; it will still 401 at the
 * route's auth guard.
 */
export function verifiedSubjectFromBearer(
  headers: Record<string, unknown> | undefined
): string | undefined {
  const claims = verifiedBearerClaims(headers);
  return typeof claims?.sub === 'string' ? claims.sub : undefined;
}

/**
 * Like `verifiedSubjectFromBearer`, but ALSO fails closed on an expired token:
 * the `sub` only when the bearer is validly signed AND unexpired. The pre-body
 * upload gate uses this so a validly-signed-but-EXPIRED token cannot force
 * `maxBytes` of heap buffering before the route's `JwtAuthGuard` 401s it — same
 * `exp` semantics as that guard (reject at `now >= exp`), same secret. A token
 * with no `exp` never expires, matching the guard.
 */
export function verifiedUnexpiredSubjectFromBearer(
  headers: Record<string, unknown> | undefined,
  nowSeconds: number = Math.floor(Date.now() / 1000)
): string | undefined {
  const claims = verifiedBearerClaims(headers);
  if (typeof claims?.sub !== 'string') {
    return undefined;
  }
  if (typeof claims.exp === 'number' && nowSeconds >= claims.exp) {
    return undefined;
  }
  return claims.sub;
}
