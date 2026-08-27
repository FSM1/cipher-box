import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Clock } from '../../common/clock';
import { Entropy } from '../../common/entropy';

export type IdentityChallengeKind = 'identity-login' | 'identity-link' | 'identity-unlink';
export type SiweChallengeKind = 'siwe-login' | 'siwe-link';

/**
 * A challenge names the operation it authorises, never only the protocol that
 * carries it. The pools are disjoint, so a challenge minted for one operation
 * cannot be spent on another.
 */
export type ChallengeKind = IdentityChallengeKind | SiweChallengeKind;

interface PendingChallenge {
  kind: ChallengeKind;
  /** Compressed identity publicKey the challenge is bound to (identity only). */
  publicKey?: string;
  expiresAt: Date;
}

/**
 * The domain tag each identity operation stamps on its challenge. The tag sits
 * inside the bytes the identity key signs, so the signature itself states what
 * it authorises; the engine pins the same table before it will sign
 * (`crates/engine/src/api/client.rs`).
 */
export const IDENTITY_CHALLENGE_PREFIXES: Readonly<Record<IdentityChallengeKind, string>> = {
  'identity-login': 'cipherbox-login:v2:',
  'identity-link': 'cipherbox-link:v2:',
  'identity-unlink': 'cipherbox-unlink:v2:',
};

/** The account-management operations that re-prove the account identity key. */
export const STEP_UP_OPERATIONS = ['link', 'unlink'] as const;
export type StepUpOperation = (typeof STEP_UP_OPERATIONS)[number];

export const STEP_UP_CHALLENGE_KINDS: Readonly<Record<StepUpOperation, IdentityChallengeKind>> = {
  link: 'identity-link',
  unlink: 'identity-unlink',
};

export function isIdentityChallengeKind(kind: ChallengeKind): kind is IdentityChallengeKind {
  return Object.hasOwn(IDENTITY_CHALLENGE_PREFIXES, kind);
}

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

  /** Issue an identity challenge for one operation, bound to a publicKey. */
  issueIdentityChallenge(
    kind: IdentityChallengeKind,
    publicKey: string
  ): { challenge: string; expiresAt: Date } {
    this.evictExpired();
    const challenge =
      IDENTITY_CHALLENGE_PREFIXES[kind] + this.entropy.randomBytes(32).toString('hex');
    const expiresAt = new Date(this.clock.now().getTime() + this.ttlMs);
    this.pending.set(challenge, { kind, publicKey, expiresAt });
    return { challenge, expiresAt };
  }

  /** Issue a SIWE nonce (16 random bytes, hex — exceeds the EIP-4361 minimum). */
  issueSiweNonce(kind: SiweChallengeKind): { nonce: string; expiresAt: Date } {
    this.evictExpired();
    const nonce = this.entropy.randomBytes(16).toString('hex');
    const expiresAt = new Date(this.clock.now().getTime() + this.ttlMs);
    this.pending.set(nonce, { kind, expiresAt });
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
    if (isIdentityChallengeKind(kind) && entry.publicKey !== publicKey) {
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
