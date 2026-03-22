import { Injectable, ExecutionContext } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

/**
 * Extends ThrottlerGuard with a bypass header for test environments.
 *
 * When `THROTTLE_BYPASS_SECRET` is set and a request includes a matching
 * `X-Throttle-Bypass` header, rate limiting is skipped. This allows SDK
 * E2E and load tests to run against staging without hitting 429s.
 *
 * Security:
 *   - Production never sets the secret, so bypass is impossible
 *   - If the env var is unset/empty, the header is ignored entirely
 *   - Constant-time comparison prevents timing attacks
 */
@Injectable()
export class BypassableThrottlerGuard extends ThrottlerGuard {
  async canActivate(context: ExecutionContext): Promise<boolean> {
    const secret = process.env.THROTTLE_BYPASS_SECRET;

    if (secret) {
      const request = context.switchToHttp().getRequest();
      const header: string | undefined = request.headers['x-throttle-bypass'];
      if (header && timingSafeEqual(header, secret)) {
        return true;
      }
    }

    return super.canActivate(context);
  }
}

/** Constant-time string comparison to prevent timing attacks on the secret. */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
