import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { describe, expect, it } from 'vitest';
import { FakeClock, FakeEntropy, fakeConfig } from '../../testing/fakes';
import { ChallengeService } from './challenge.service';
import type { EmailOtpService } from './email-otp.service';
import type { GoogleOAuthService } from './google-oauth.service';
import { IdentityExchangeService } from './identity-exchange.service';
import type { IdentitySubjectService } from './identity-subject.service';
import type { IdentityTokenService } from './identity-token.service';
import { SIWE_LOGIN_STATEMENT, SiweService } from './siwe.service';

const ORIGIN = 'http://localhost:5173';

/** Real SIWE verification and nonces; the provider, subject and token seams stubbed. */
function exchange() {
  const config = fakeConfig({ CORS_ALLOWED_ORIGINS: ORIGIN }).service;
  const challenges = new ChallengeService(new FakeClock(), new FakeEntropy(), config);
  const google = {
    verify: () => Promise.resolve({ subject: 'google-subject', email: 'member@example.test' }),
  } as unknown as GoogleOAuthService;
  const emailOtp = { verify: () => 'member@example.test' } as unknown as EmailOtpService;
  const subjects = {
    resolve: (kind: string) => Promise.resolve(`subject-for-${kind}`),
  } as unknown as IdentitySubjectService;
  const tokens = {
    sign: () => Promise.resolve({ token: 'header.payload.signature', expiresAt: new Date(0) }),
  } as unknown as IdentityTokenService;
  const service = new IdentityExchangeService(
    google,
    emailOtp,
    new SiweService(config),
    challenges,
    subjects,
    tokens
  );
  return { service, challenges };
}

describe('IdentityExchangeService display', () => {
  it('displays the address an email sign-in verified', async () => {
    const grant = await exchange().service.fromEmailCode('Member@Example.test', '123456');

    expect(grant.display).toBe('member@example.test');
  });

  it('displays the Google email, never the Google subject', async () => {
    const grant = await exchange().service.fromGoogleToken('id.token.value');

    expect(grant.display).toBe('member@example.test');
    expect(grant.display).not.toContain('google-subject');
  });

  it('displays a wallet as its truncated checksummed address, and never the full one', async () => {
    const { service, challenges } = exchange();
    const account = privateKeyToAccount(generatePrivateKey());
    const { nonce } = challenges.issueSiweNonce('siwe-login');
    const message = createSiweMessage({
      address: account.address,
      chainId: 1,
      domain: 'localhost:5173',
      nonce,
      uri: ORIGIN,
      version: '1',
      statement: SIWE_LOGIN_STATEMENT,
    });

    const grant = await service.fromWalletSignature(
      message,
      await account.signMessage({ message })
    );

    expect(grant.display).toBe(`${account.address.slice(0, 6)}...${account.address.slice(-4)}`);
    const serialized = JSON.stringify(grant).toLowerCase();
    expect(serialized).not.toContain(account.address.toLowerCase());
  });
});
