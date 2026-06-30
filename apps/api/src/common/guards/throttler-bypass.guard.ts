import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { timingSafeEqual } from 'node:crypto';

/**
 * Extends ThrottlerGuard with a bypass header for test environments.
 *
 * - In the test environment (NODE_ENV === 'test') rate limiting is disabled
 *   outright. The default tracker is per-IP, so a full E2E suite hammering the
 *   API from localhost otherwise shares one bucket and exhausts the per-route
 *   `@Throttle` limits (e.g. 30 resolves/min) — surfacing as spurious 429s →
 *   null resolves. The header-bypass alone is fragile (it needs the secret set
 *   on the API process AND the header on every request); the test env should
 *   simply not rate-limit at all.
 * - On staging (NODE_ENV !== 'production'/'test') a matching X-Throttle-Bypass
 *   header skips rate limiting when THROTTLE_BYPASS_SECRET is configured.
 *
 * Security:
 *   - Production always enforces rate limits (NODE_ENV check)
 *   - If the env var is unset/empty, the header is ignored entirely
 *   - Uses crypto.timingSafeEqual to prevent timing attacks
 */
@Injectable()
export class BypassableThrottlerGuard extends ThrottlerGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Test environments disable rate limiting entirely (see class doc).
    if (process.env.NODE_ENV === 'test') {
      return true;
    }

    const secret = process.env.THROTTLE_BYPASS_SECRET;

    if (secret && process.env.NODE_ENV !== 'production') {
      const request = context.switchToHttp().getRequest();
      const rawHeader = request.headers['x-throttle-bypass'];
      const header = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
      if (header && safeEqual(header, secret)) {
        return true;
      }
    }

    return super.canActivate(context);
  }
}

/** Constant-time string comparison using Node.js crypto. */
function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}
