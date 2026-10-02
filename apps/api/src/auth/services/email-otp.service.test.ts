import { HttpException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { beforeEach, describe, expect, it } from 'vitest';
import { CapturingMailProvider, FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { EmailOtpService } from './email-otp.service';

const EMAIL = 'member@example.com';
const ACCOUNT = '11111111-1111-4111-8111-111111111111';
const OTHER_ACCOUNT = '22222222-2222-4222-8222-222222222222';

describe('EmailOtpService', () => {
  let clock: FakeClock;
  let mail: CapturingMailProvider;
  let service: EmailOtpService;

  const lastCode = () => mail.lastCode();

  beforeEach(() => {
    clock = new FakeClock();
    mail = new CapturingMailProvider();
    service = new EmailOtpService(clock, new FakeEntropy(), mail, fakeConfig({}).service);
  });

  it('delivers a six-digit code and accepts it once', async () => {
    await service.send(EMAIL, 'login');

    expect(mail.delivered).toHaveLength(1);
    expect(lastCode()).toMatch(/^[0-9]{6}$/);

    expect(() => service.verify(EMAIL, lastCode(), 'login')).not.toThrow();
    // Single-use: the same code cannot be spent twice.
    expect(() => service.verify(EMAIL, lastCode(), 'login')).toThrow(UnauthorizedException);
  });

  it('refuses a code CipherBox never issued', () => {
    expect(() => service.verify(EMAIL, '000000', 'login')).toThrow(UnauthorizedException);
  });

  it('refuses a code that is not the one issued', async () => {
    await service.send(EMAIL, 'login');
    const wrong = lastCode() === '000000' ? '111111' : '000000';
    expect(() => service.verify(EMAIL, wrong, 'login')).toThrow(UnauthorizedException);
  });

  it('refuses an expired code', async () => {
    await service.send(EMAIL, 'login');
    const code = lastCode();
    clock.advanceMs(300_001);
    expect(() => service.verify(EMAIL, code, 'login')).toThrow(UnauthorizedException);
  });

  it('refuses a code issued for a different address', async () => {
    await service.send(EMAIL, 'login');
    expect(() => service.verify('someone-else@example.com', lastCode(), 'login')).toThrow(
      UnauthorizedException
    );
  });

  it('treats case and surrounding space as the same address', async () => {
    await service.send('  MEMBER@Example.COM ', 'login');
    expect(mail.delivered[0].to).toBe(EMAIL);
    expect(() => service.verify(EMAIL, lastCode(), 'login')).not.toThrow();
  });

  it('voids the code after a run of wrong guesses', async () => {
    await service.send(EMAIL, 'login');
    const code = lastCode();
    const wrong = code === '000000' ? '111111' : '000000';

    // The messages are asserted, not just the status: both refusals are a 401,
    // so a budget that never actually ran out would read the same here.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(() => service.verify(EMAIL, wrong, 'login')).toThrow(/Incorrect verification code/);
    }
    // The budget is spent, so even the right code no longer opens it.
    expect(() => service.verify(EMAIL, code, 'login')).toThrow(/Too many attempts/);
  });

  it('still opens on the right code after a few wrong guesses', async () => {
    await service.send(EMAIL, 'login');
    const code = lastCode();
    const wrong = code === '000000' ? '111111' : '000000';

    for (let attempt = 0; attempt < 4; attempt += 1) {
      expect(() => service.verify(EMAIL, wrong, 'login')).toThrow(UnauthorizedException);
    }

    expect(service.verify(EMAIL, code, 'login')).toBe(EMAIL);
  });

  it('caps how many codes one address can request in a window', async () => {
    for (let send = 0; send < 5; send += 1) await service.send(EMAIL, 'login');
    await expect(service.send(EMAIL, 'login')).rejects.toThrow(HttpException);

    clock.advanceMs(15 * 60 * 1000 + 1);
    await expect(service.send(EMAIL, 'login')).resolves.toBeUndefined();
  });

  it('leaves no code outstanding when delivery fails', async () => {
    await service.send(EMAIL, 'login');
    const firstCode = lastCode();

    mail.failNext = true;
    await expect(service.send(EMAIL, 'login')).rejects.toThrow(ServiceUnavailableException);

    // The replaced code is gone and the undelivered one was never live.
    expect(() => service.verify(EMAIL, firstCode, 'login')).toThrow(UnauthorizedException);
  });

  it('refuses a sign-in code presented as a link code', async () => {
    await service.send(EMAIL, 'login');
    expect(() => service.verify(EMAIL, lastCode(), 'link', ACCOUNT)).toThrow(UnauthorizedException);
  });

  it('refuses a link code presented as a sign-in code', async () => {
    await service.send(EMAIL, 'link', ACCOUNT);
    expect(() => service.verify(EMAIL, lastCode(), 'login')).toThrow(UnauthorizedException);
  });

  it('keeps a code of one purpose outstanding when the other purpose issues one', async () => {
    await service.send(EMAIL, 'login');
    const signIn = lastCode();
    await service.send(EMAIL, 'link', ACCOUNT);

    expect(service.verify(EMAIL, signIn, 'login')).toBe(EMAIL);
    expect(service.verify(EMAIL, lastCode(), 'link', ACCOUNT)).toBe(EMAIL);
  });

  it('refuses a link code to an account that did not ask for it, at no cost to the owner', async () => {
    await service.send(EMAIL, 'link', ACCOUNT);
    const code = lastCode();

    for (let attempt = 0; attempt < 6; attempt += 1) {
      expect(() => service.verify(EMAIL, code, 'link', OTHER_ACCOUNT)).toThrow(
        /No verification code is outstanding/
      );
    }
    expect(service.verify(EMAIL, code, 'link', ACCOUNT)).toBe(EMAIL);
  });

  it('charges one send budget per address across both purposes', async () => {
    for (let send = 0; send < 3; send += 1) await service.send(EMAIL, 'login');
    for (let send = 0; send < 2; send += 1) await service.send(EMAIL, 'link', ACCOUNT);

    await expect(service.send(EMAIL, 'login')).rejects.toThrow(HttpException);
    await expect(service.send(EMAIL, 'link', ACCOUNT)).rejects.toThrow(HttpException);
  });

  it('hands the purpose to the mail provider', async () => {
    await service.send(EMAIL, 'login');
    await service.send(EMAIL, 'link', ACCOUNT);

    expect(mail.delivered.map((sent) => sent.purpose)).toEqual(['login', 'link']);
  });
});
