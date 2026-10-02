import { Logger } from '@nestjs/common';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeConfig } from '../../testing/fakes';
import {
  buildMailProvider,
  LoggingMailProvider,
  SendGridMailProvider,
  verificationMessage,
} from './mail.provider';

const SENDGRID = {
  MAIL_PROVIDER: 'sendgrid',
  SENDGRID_API_KEY: 'sg-key',
  MAIL_FROM_ADDRESS: 'noreply@cipherbox.cc',
};

function build(values: Record<string, string | undefined>) {
  return buildMailProvider(fakeConfig(values).service);
}

describe('buildMailProvider', () => {
  it('refuses to boot a deployed environment with no provider configured', () => {
    expect(() => build({ NODE_ENV: 'production' })).toThrow(/MAIL_PROVIDER is required/);
    expect(() => build({ NODE_ENV: 'staging' })).toThrow(/MAIL_PROVIDER is required/);
  });

  it('refuses a deployed environment configured to deliver nothing', () => {
    expect(() => build({ NODE_ENV: 'production', MAIL_PROVIDER: 'log' })).toThrow(
      /delivers no mail/
    );
  });

  it('refuses a provider it cannot honour rather than falling back', () => {
    expect(() => build({ NODE_ENV: 'production', MAIL_PROVIDER: 'carrier-pigeon' })).toThrow(
      /Unknown MAIL_PROVIDER/
    );
  });

  it('refuses a half-configured provider', () => {
    expect(() => build({ NODE_ENV: 'production', MAIL_PROVIDER: 'sendgrid' })).toThrow(
      /requires SENDGRID_API_KEY and MAIL_FROM_ADDRESS/
    );
    expect(() =>
      build({ NODE_ENV: 'production', MAIL_PROVIDER: 'sendgrid', SENDGRID_API_KEY: 'sg-key' })
    ).toThrow(/requires SENDGRID_API_KEY and MAIL_FROM_ADDRESS/);
  });

  it('builds the configured provider in a deployed environment', () => {
    expect(build({ NODE_ENV: 'production', ...SENDGRID })).toBeInstanceOf(SendGridMailProvider);
  });

  it('falls back to logging delivery only in development and test', () => {
    expect(build({ NODE_ENV: 'development' })).toBeInstanceOf(LoggingMailProvider);
    expect(build({ NODE_ENV: 'test' })).toBeInstanceOf(LoggingMailProvider);
  });
});

describe('SendGridMailProvider', () => {
  // Unstubbed however the test ended: a failed assertion would otherwise leave
  // the stub installed for every suite that runs after it.
  afterEach(() => vi.unstubAllGlobals());

  it('addresses the message to the recipient and reports the code', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);

    await new SendGridMailProvider('sg-key', 'noreply@cipherbox.cc').sendVerificationCode(
      'member@example.com',
      '123456',
      'login'
    );

    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body as string);
    expect(body.personalizations[0].to[0].email).toBe('member@example.com');
    expect(body.from.email).toBe('noreply@cipherbox.cc');
    expect(body.content[0].value).toContain('123456');
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer sg-key');
  });

  it('treats a refused send as a failure rather than reporting success', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('detail', { status: 429 })));

    await expect(
      new SendGridMailProvider('sg-key', 'noreply@cipherbox.cc').sendVerificationCode(
        'member@example.com',
        '123456',
        'login'
      )
    ).rejects.toThrow(/status 429/);
  });
});

describe('verification mail by purpose', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('gives a link code its own subject and body', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 202 }));
    vi.stubGlobal('fetch', fetchMock);
    const provider = new SendGridMailProvider('sg-key', 'noreply@cipherbox.cc');

    await provider.sendVerificationCode('member@example.com', '123456', 'login');
    await provider.sendVerificationCode('member@example.com', '654321', 'link');

    const [signIn, link] = fetchMock.mock.calls.map(([, init]) => JSON.parse(init.body as string));
    expect(link.subject).not.toBe(signIn.subject);
    expect(link.subject).toBe(verificationMessage('654321', 'link').subject);
    expect(link.content[0].value).toContain('654321');
    expect(link.content[0].value).toMatch(/add this address as a login/);
    expect(link.content[0].value).toMatch(/Share this code with no one/);
    expect(signIn.content[0].value).toContain('123456');
    expect(signIn.content[0].value).not.toMatch(/add this address/);
  });

  it('logs one line format for both purposes', async () => {
    const warn = vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    const provider = new LoggingMailProvider();

    await provider.sendVerificationCode('member@example.com', '123456', 'login');
    await provider.sendVerificationCode('member@example.com', '654321', 'link');

    expect(warn.mock.calls.map(([line]) => line)).toEqual([
      'Verification code for member@example.com: 123456',
      'Verification code for member@example.com: 654321',
    ]);
  });
});
