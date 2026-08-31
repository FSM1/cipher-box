/**
 * A CipherBox identity token, minted through the shipped identity exchange.
 *
 * The device-approval rendezvous binds an account to an identity subject, so a
 * two-session spec needs one real token that both sessions name. Of the three
 * methods the API offers, only the wallet one closes with no party outside this
 * stack: the suite signs the EIP-4361 message itself, and the API verifies it
 * and mints the same token every other method mints (ADR 0008 D2).
 */

import { createIdentityExchange, type IdentityCredential } from '@cipherbox/login';
import { generatePrivateKey, privateKeyToAccount } from 'viem/accounts';
import { createSiweMessage } from 'viem/siwe';
import { mainnet } from 'viem/chains';

/** What the login route states, and so what the SIWE message must state. */
const STATEMENT = 'Sign in to CipherBox encrypted storage';

/** Where the API answers this run. The bundle under test reads the same value. */
export function apiBaseUrl(): string {
  return (process.env.VITE_API_URL ?? 'http://localhost:3000').replace(/\/+$/, '');
}

/**
 * Mints a token for a wallet nobody else in the run holds, so each spec owns its
 * own identity subject and none shares another's per-account rate budget.
 */
export async function mintIdentity(origin: string): Promise<IdentityCredential> {
  const exchange = createIdentityExchange(apiBaseUrl());
  const account = privateKeyToAccount(generatePrivateKey());
  const message = createSiweMessage({
    address: account.address,
    chainId: mainnet.id,
    // The API validates the domain against its CORS origins, and the suite is
    // served from one of them.
    domain: new URL(origin).host,
    nonce: await exchange.walletNonce(),
    uri: origin,
    version: '1',
    statement: STATEMENT,
  });
  return exchange.fromWalletSignature(message, await account.signMessage({ message }));
}
