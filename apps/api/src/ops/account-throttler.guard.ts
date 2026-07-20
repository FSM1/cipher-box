import { Injectable } from '@nestjs/common';
import { ThrottlerGuard } from '@nestjs/throttler';

/**
 * Global throttler keyed by the authenticated account when present, falling
 * back to the client IP otherwise.
 *
 * The blueprint's mailbox limits are per SENDER account (post) and per
 * RECIPIENT mailbox (poll/ack) — both the authenticated account — so the
 * tracker must be the account, not the IP. Buckets are already separated per
 * route+throttler by the base `generateKey`, so this only widens the tracker.
 *
 * The account is read from the bearer's `sub` WITHOUT verification: this is a
 * rate-limit key, not an authorization decision. A forged token cannot exploit
 * it — the route's JwtAuthGuard rejects any unsigned/invalid token with 401
 * before the handler runs, so a forged `sub` can neither store a message nor
 * reach the existence oracle. Unauthenticated routes (auth, health) carry no
 * bearer and keep the base IP tracker unchanged.
 */
@Injectable()
export class AccountThrottlerGuard extends ThrottlerGuard {
  protected async getTracker(req: Record<string, unknown>): Promise<string> {
    const subject = subjectFromBearer(req.headers as Record<string, unknown> | undefined);
    if (subject) {
      return `acct:${subject}`;
    }
    return super.getTracker(req);
  }
}

function subjectFromBearer(headers: Record<string, unknown> | undefined): string | undefined {
  const authorization = headers?.authorization;
  if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) {
    return undefined;
  }
  const parts = authorization.slice('Bearer '.length).split('.');
  if (parts.length !== 3) {
    return undefined;
  }
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as {
      sub?: unknown;
    };
    return typeof payload.sub === 'string' ? payload.sub : undefined;
  } catch {
    return undefined;
  }
}
