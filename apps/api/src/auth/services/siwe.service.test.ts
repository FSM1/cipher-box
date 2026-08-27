import { UnauthorizedException } from '@nestjs/common';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { describe, expect, it } from 'vitest';
import { fakeConfig } from '../../testing/fakes';
import { SIWE_LINK_STATEMENT, SIWE_LOGIN_STATEMENT, SiweService } from './siwe.service';

/**
 * One nonce pool serves signing in and linking, and `POST /auth/siwe/challenge`
 * is unauthenticated — so the statement is the only field that tells a verifier
 * which intent the member was shown.
 */
describe('SiweService intent binding', () => {
  const NONCE = 'nonce12345678';
  const service = new SiweService(
    fakeConfig({ CORS_ALLOWED_ORIGINS: 'http://localhost:5173' }).service
  );

  async function signedWith(statement: string | undefined) {
    const account = privateKeyToAccount(generatePrivateKey());
    const message = createSiweMessage({
      address: account.address,
      chainId: 1,
      domain: 'localhost:5173',
      nonce: NONCE,
      uri: 'http://localhost:5173',
      version: '1',
      statement,
    });
    return { address: account.address, message, signature: await account.signMessage({ message }) };
  }

  it('accepts a message stating the intent the surface serves', async () => {
    const { address, message, signature } = await signedWith(SIWE_LINK_STATEMENT);
    await expect(
      service.verifySiweMessage(message, signature, NONCE, SIWE_LINK_STATEMENT)
    ).resolves.toBe(address);
  });

  it('refuses a phished sign-in signature presented as a link', async () => {
    const { message, signature } = await signedWith(SIWE_LOGIN_STATEMENT);
    await expect(
      service.verifySiweMessage(message, signature, NONCE, SIWE_LINK_STATEMENT)
    ).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a link signature presented as a sign-in', async () => {
    const { message, signature } = await signedWith(SIWE_LINK_STATEMENT);
    await expect(
      service.verifySiweMessage(message, signature, NONCE, SIWE_LOGIN_STATEMENT)
    ).rejects.toThrow(UnauthorizedException);
  });

  it('refuses a message that states no intent at all', async () => {
    const { message, signature } = await signedWith(undefined);
    await expect(
      service.verifySiweMessage(message, signature, NONCE, SIWE_LOGIN_STATEMENT)
    ).rejects.toThrow(UnauthorizedException);
  });
});
