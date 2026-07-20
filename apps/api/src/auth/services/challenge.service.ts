import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Clock } from '../../common/clock';
import { Entropy } from '../../common/entropy';

export type ChallengeKind = 'identity' | 'siwe';

interface PendingChallenge {
  kind: ChallengeKind;
  /** Compressed identity publicKey the challenge is bound to (identity only). */
  publicKey?: string;
  expiresAt: Date;
}

export const IDENTITY_CHALLENGE_PREFIX = 'cipherbox-login:v2:';

/**
 * Single-use, server-issued login challenges.
 *
 * Held in memory on purpose: challenges are ephemeral (minutes) and the
 * data model is fixed to users/auth_methods/refresh_tokens plus the
 * registry tables (blueprint/api.md, "Data model (complete)") — no
 * challenge table exists. A process restart merely voids in-flight
 * challenges; the client requests a new one.
 */
@Injectable()
export class ChallengeService {
  private readonly pending = new Map<string, PendingChallenge>();
  private readonly ttlMs: number;

  constructor(
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    configService: ConfigService
  ) {
    this.ttlMs = Number(configService.get('CHALLENGE_TTL_SECONDS') ?? 300) * 1000;
  }

  /** Issue a challenge bound to an identity publicKey. */
  issueIdentityChallenge(publicKey: string): { challenge: string; expiresAt: Date } {
    this.evictExpired();
    const challenge = IDENTITY_CHALLENGE_PREFIX + this.entropy.randomBytes(32).toString('hex');
    const expiresAt = new Date(this.clock.now().getTime() + this.ttlMs);
    this.pending.set(challenge, { kind: 'identity', publicKey, expiresAt });
    return { challenge, expiresAt };
  }

  /** Issue a SIWE nonce (16 random bytes, hex — exceeds the EIP-4361 minimum). */
  issueSiweNonce(): { nonce: string; expiresAt: Date } {
    this.evictExpired();
    const nonce = this.entropy.randomBytes(16).toString('hex');
    const expiresAt = new Date(this.clock.now().getTime() + this.ttlMs);
    this.pending.set(nonce, { kind: 'siwe', expiresAt });
    return { nonce, expiresAt };
  }

  /**
   * Consume a challenge: it must exist, match the kind (and bound publicKey
   * for identity), and be unexpired. Single-use — consuming removes it.
   */
  consume(value: string, kind: ChallengeKind, publicKey?: string): void {
    const entry = this.pending.get(value);
    if (!entry || entry.kind !== kind) {
      throw new UnauthorizedException('Unknown or already-used challenge');
    }
    this.pending.delete(value);
    if (entry.expiresAt.getTime() <= this.clock.now().getTime()) {
      throw new UnauthorizedException('Challenge expired');
    }
    if (kind === 'identity' && entry.publicKey !== publicKey) {
      throw new UnauthorizedException('Challenge was issued for a different publicKey');
    }
  }

  private evictExpired(): void {
    const now = this.clock.now().getTime();
    for (const [value, entry] of this.pending) {
      if (entry.expiresAt.getTime() <= now) {
        this.pending.delete(value);
      }
    }
  }
}
