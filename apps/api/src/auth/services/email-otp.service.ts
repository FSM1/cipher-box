import {
  HttpException,
  HttpStatus,
  Injectable,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { Clock } from '../../common/clock';
import { Entropy } from '../../common/entropy';
import { MailProvider } from './mail.provider';

const CODE_DIGITS = 6;
const CODE_CEILING = 10 ** CODE_DIGITS;
/** Largest multiple of the ceiling inside 2^32, so rejection sampling stays unbiased. */
const SAMPLE_LIMIT = Math.floor(2 ** 32 / CODE_CEILING) * CODE_CEILING;

const MAX_VERIFY_ATTEMPTS = 5;
const MAX_SENDS_PER_WINDOW = 5;
const SEND_WINDOW_MS = 15 * 60 * 1000;

/**
 * Bounds the table against an address-rotating flood. The oldest address gives
 * way rather than new sends being refused, so a flood costs a member a
 * re-request instead of locking them out; the ceiling sits far above what the
 * per-IP auth throttle can drive inside one send window.
 */
const MAX_TRACKED_ADDRESSES = 10_000;

interface IssuedCode {
  salt: Buffer;
  digest: Buffer;
  expiresAt: Date;
  attemptsLeft: number;
}

/**
 * One address's state. The send window outlives the code it issued, so the
 * entry — not the code — is the unit that expires, and the budget cannot be
 * reset by simply letting a code lapse.
 */
interface AddressEntry {
  code: IssuedCode | null;
  sends: number;
  windowEndsAt: Date;
}

/**
 * CipherBox's own passwordless email (ADR 0008 D1): it issues the code, it
 * verifies the code, and it owns delivery.
 *
 * Held in memory for the same reason `ChallengeService` is: the data model is
 * fixed by blueprint/api.md and has no table for state that lives minutes. A
 * restart voids codes in flight; the member requests another.
 */
@Injectable()
export class EmailOtpService {
  private readonly tracked = new Map<string, AddressEntry>();
  private readonly ttlMs: number;

  constructor(
    private readonly clock: Clock,
    private readonly entropy: Entropy,
    private readonly mail: MailProvider,
    configService: ConfigService
  ) {
    this.ttlMs = Number(configService.get('EMAIL_OTP_TTL_SECONDS') ?? 300) * 1000;
  }

  /** Issue a code and deliver it. Replaces any code already outstanding. */
  async send(email: string): Promise<void> {
    const address = normalizeEmail(email);
    this.evictExpired();

    const now = this.clock.now();
    const entry = this.chargeSend(address, now);

    const code = this.generateCode();
    const salt = this.entropy.randomBytes(16);
    entry.code = {
      salt,
      digest: digestOf(salt, code),
      expiresAt: new Date(now.getTime() + this.ttlMs),
      attemptsLeft: MAX_VERIFY_ATTEMPTS,
    };

    try {
      await this.mail.sendVerificationCode(address, code);
    } catch {
      // Undeliverable is not "issued": leaving it live would let a member sit
      // waiting on a code that is never coming.
      entry.code = null;
      throw new ServiceUnavailableException('The verification code could not be delivered');
    }
  }

  /**
   * Consume a code. Single-use, attempt-capped, and expiry-checked — a wrong
   * guess costs an attempt, and running out voids the code entirely.
   */
  verify(email: string, code: string): void {
    const address = normalizeEmail(email);
    this.evictExpired();

    const issued = this.tracked.get(address)?.code;
    if (!issued) {
      throw new UnauthorizedException('No verification code is outstanding for this address');
    }
    if (issued.expiresAt.getTime() <= this.clock.now().getTime()) {
      this.clearCode(address);
      throw new UnauthorizedException('The verification code has expired');
    }

    issued.attemptsLeft -= 1;
    if (issued.attemptsLeft < 0) {
      this.clearCode(address);
      throw new UnauthorizedException('Too many attempts — request a new code');
    }

    if (!timingSafeEqual(digestOf(issued.salt, code), issued.digest)) {
      throw new UnauthorizedException('Incorrect verification code');
    }
    this.clearCode(address);
  }

  /** Uniform over the code space: a biased modulo would thin the keyspace. */
  private generateCode(): string {
    let sample: number;
    do {
      sample = this.entropy.randomBytes(4).readUInt32BE(0);
    } while (sample >= SAMPLE_LIMIT);
    return String(sample % CODE_CEILING).padStart(CODE_DIGITS, '0');
  }

  private chargeSend(address: string, now: Date): AddressEntry {
    const entry = this.tracked.get(address);
    if (!entry) {
      const fresh: AddressEntry = {
        code: null,
        sends: 1,
        windowEndsAt: new Date(now.getTime() + SEND_WINDOW_MS),
      };
      this.tracked.set(address, fresh);
      this.evictOverflow();
      return fresh;
    }
    if (entry.sends >= MAX_SENDS_PER_WINDOW) {
      throw new HttpException(
        'Too many verification codes requested for this address',
        HttpStatus.TOO_MANY_REQUESTS
      );
    }
    entry.sends += 1;
    return entry;
  }

  private clearCode(address: string): void {
    const entry = this.tracked.get(address);
    if (entry) entry.code = null;
  }

  private evictExpired(): void {
    const now = this.clock.now().getTime();
    for (const [address, entry] of this.tracked) {
      if (entry.windowEndsAt.getTime() <= now) this.tracked.delete(address);
    }
  }

  private evictOverflow(): void {
    while (this.tracked.size > MAX_TRACKED_ADDRESSES) {
      const [oldest] = this.tracked.keys();
      this.tracked.delete(oldest);
    }
  }
}

/** One address is one identity: case and surrounding space never distinguish two. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}

function digestOf(salt: Buffer, code: string): Buffer {
  return createHmac('sha256', salt).update(code).digest();
}
