import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';
import { timingSafeEqual } from 'node:crypto';

/**
 * Extends ThrottlerGuard with a bypass header for test environments.
 *
 * When THROTTLE_BYPASS_SECRET is set, NODE_ENV is not 'production', and
 * a request includes a matching X-Throttle-Bypass header, rate limiting
 * is skipped. This allows SDK E2E and load tests to run against staging
 * without hitting 429s.
 *
 * Security:
 *   - Production always enforces rate limits (NODE_ENV check)
 *   - If the env var is unset/empty, the header is ignored entirely
 *   - Uses crypto.timingSafeEqual to prevent timing attacks
 */
@Injectable()
export class BypassableThrottlerGuard extends ThrottlerGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
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
  if (a.length !== b.length) return false;
  return timingSafeEqual(Buffer.from(a), Buffer.from(b));
}
