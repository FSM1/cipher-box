import { ConfigService } from '@nestjs/config';
import type { EmailCodePurpose } from '../auth/services/email-otp.service';
import { MailProvider } from '../auth/services/mail.provider';
import { Clock } from '../common/clock';
import { Entropy } from '../common/entropy';

export class FakeClock extends Clock {
  private current: Date;

  constructor(start = new Date('2026-01-01T00:00:00Z')) {
    super();
    this.current = start;
  }

  now(): Date {
    return new Date(this.current);
  }

  advanceMs(ms: number): void {
    this.current = new Date(this.current.getTime() + ms);
  }
}

/** Deterministic, collision-free byte source: a big-endian counter. */
export class FakeEntropy extends Entropy {
  private counter = 0;

  randomBytes(length: number): Buffer {
    const buffer = Buffer.alloc(length);
    this.counter += 1;
    buffer.writeUInt32BE(this.counter, length - 4);
    return buffer;
  }
}

/** Mutable ConfigService stand-in backed by a plain object. */
export function fakeConfig(values: Record<string, string | undefined>): {
  service: ConfigService;
  values: Record<string, string | undefined>;
} {
  const service = {
    get: (key: string) => values[key],
  } as unknown as ConfigService;
  return { service, values };
}

/** Captures each delivered code, so a test can present the real one. */
export class CapturingMailProvider extends MailProvider {
  delivered: { to: string; code: string; purpose: EmailCodePurpose }[] = [];
  /** Refuse the next send, as a provider outage would. */
  failNext = false;

  sendVerificationCode(to: string, code: string, purpose: EmailCodePurpose): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error('the provider refused the message'));
    }
    this.delivered.push({ to, code, purpose });
    return Promise.resolve();
  }

  lastCode(): string {
    return this.delivered[this.delivered.length - 1].code;
  }
}
