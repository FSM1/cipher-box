import { HttpException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { beforeEach, describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { EmailOtpService } from './email-otp.service';
import { MailProvider } from './mail.provider';

const EMAIL = 'member@example.com';

/** Captures what was delivered, so a test can present the real code. */
class CapturingMailProvider extends MailProvider {
  delivered: { to: string; code: string }[] = [];
  failNext = false;

  sendVerificationCode(to: string, code: string): Promise<void> {
    if (this.failNext) {
      this.failNext = false;
      return Promise.reject(new Error('the provider refused the message'));
    }
    this.delivered.push({ to, code });
    return Promise.resolve();
  }
}

describe('EmailOtpService', () => {
  let clock: FakeClock;
  let mail: CapturingMailProvider;
  let service: EmailOtpService;

  const lastCode = () => mail.delivered[mail.delivered.length - 1].code;

  beforeEach(() => {
    clock = new FakeClock();
    mail = new CapturingMailProvider();
    service = new EmailOtpService(clock, new FakeEntropy(), mail, fakeConfig({}).service);
  });

  it('delivers a six-digit code and accepts it once', async () => {
    await service.send(EMAIL);

    expect(mail.delivered).toHaveLength(1);
    expect(lastCode()).toMatch(/^[0-9]{6}$/);

    expect(() => service.verify(EMAIL, lastCode())).not.toThrow();
    // Single-use: the same code cannot be spent twice.
    expect(() => service.verify(EMAIL, lastCode())).toThrow(UnauthorizedException);
  });

  it('refuses a code CipherBox never issued', () => {
    expect(() => service.verify(EMAIL, '000000')).toThrow(UnauthorizedException);
  });

  it('refuses a code that is not the one issued', async () => {
    await service.send(EMAIL);
    const wrong = lastCode() === '000000' ? '111111' : '000000';
    expect(() => service.verify(EMAIL, wrong)).toThrow(UnauthorizedException);
  });

  it('refuses an expired code', async () => {
    await service.send(EMAIL);
    const code = lastCode();
    clock.advanceMs(300_001);
    expect(() => service.verify(EMAIL, code)).toThrow(UnauthorizedException);
  });

  it('refuses a code issued for a different address', async () => {
    await service.send(EMAIL);
    expect(() => service.verify('someone-else@example.com', lastCode())).toThrow(
      UnauthorizedException
    );
  });

  it('treats case and surrounding space as the same address', async () => {
    await service.send('  MEMBER@Example.COM ');
    expect(mail.delivered[0].to).toBe(EMAIL);
    expect(() => service.verify(EMAIL, lastCode())).not.toThrow();
  });

  it('voids the code after a run of wrong guesses', async () => {
    await service.send(EMAIL);
    const code = lastCode();
    const wrong = code === '000000' ? '111111' : '000000';

    // The messages are asserted, not just the status: both refusals are a 401,
    // so a budget that never actually ran out would read the same here.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(() => service.verify(EMAIL, wrong)).toThrow(/Incorrect verification code/);
    }
    // The budget is spent, so even the right code no longer opens it.
    expect(() => service.verify(EMAIL, code)).toThrow(/Too many attempts/);
  });

  it('still opens on the right code after a few wrong guesses', async () => {
    await service.send(EMAIL);
    const code = lastCode();
    const wrong = code === '000000' ? '111111' : '000000';

    for (let attempt = 0; attempt < 4; attempt += 1) {
      expect(() => service.verify(EMAIL, wrong)).toThrow(UnauthorizedException);
    }

    expect(service.verify(EMAIL, code)).toBe(EMAIL);
  });

  it('caps how many codes one address can request in a window', async () => {
    for (let send = 0; send < 5; send += 1) await service.send(EMAIL);
    await expect(service.send(EMAIL)).rejects.toThrow(HttpException);

    clock.advanceMs(15 * 60 * 1000 + 1);
    await expect(service.send(EMAIL)).resolves.toBeUndefined();
  });

  it('leaves no code outstanding when delivery fails', async () => {
    await service.send(EMAIL);
    const firstCode = lastCode();

    mail.failNext = true;
    await expect(service.send(EMAIL)).rejects.toThrow(ServiceUnavailableException);

    // The replaced code is gone and the undelivered one was never live.
    expect(() => service.verify(EMAIL, firstCode)).toThrow(UnauthorizedException);
  });
});
