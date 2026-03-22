/**
 * SDK E2E Test Harness
 *
 * Creates authenticated CipherBoxClient instances backed by real API accounts.
 * Extracted from packages/sdk/src/__tests__/integration.test.ts pattern.
 *
 * Each call to createTestContext() creates a unique user via /auth/test-login,
 * initializes their vault, and returns a ready-to-use CipherBoxClient.
 */

import { CipherBoxClient } from '@cipherbox/sdk';
import { setApiClientConfig } from '@cipherbox/api-client';
import { initializeVault, encryptVaultKeys } from '@cipherbox/core';
import { deriveIpnsName, hexToBytes, bytesToHex } from '@cipherbox/crypto';

const API_URL = process.env.SDK_E2E_API_URL ?? 'http://localhost:3000';
const SECRET = process.env.SDK_E2E_SECRET ?? 'e2e-test-secret-do-not-use-in-production';

/** Core account data returned by createTestAccount (shared between sdk-e2e and load tests). */
export interface TestAccount {
  client: CipherBoxClient;
  accessToken: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  rootIpnsName: string;
  rootFolderKey: Uint8Array;
  rootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  email: string;
}

export interface TestContext extends TestAccount {
  /** Destroy the client and zero key material */
  cleanup: () => void;
}

export interface CreateAccountOptions {
  apiUrl?: string;
  secret?: string;
  label: string;
  emailPrefix?: string;
}

/**
 * Create a test account with an initialized vault and CipherBoxClient.
 * This is the shared core used by both sdk-e2e (createTestContext) and
 * load tests (createPoolClient).
 */
export async function createTestAccount(opts: CreateAccountOptions): Promise<TestAccount> {
  const apiUrl = opts.apiUrl ?? API_URL;
  const secret = opts.secret ?? SECRET;
  const prefix = opts.emailPrefix ?? 'sdk-e2e';
  const email = `${prefix}-${opts.label}-${Date.now()}@example.com`;

  // 1. Authenticate
  const loginRes = await fetch(`${apiUrl}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  });
  if (!loginRes.ok) {
    throw new Error(`test-login failed (${loginRes.status}): ${await loginRes.text()}`);
  }
  const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
  const publicKey = hexToBytes(publicKeyHex);
  const privateKey = hexToBytes(privateKeyHex);

  // 2. Initialize vault
  const vault = await initializeVault(privateKey);
  const encrypted = await encryptVaultKeys(vault, publicKey);
  const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

  // 3. Register vault on server
  const initRes = await fetch(`${apiUrl}/vault/init`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      ownerPublicKey: bytesToHex(publicKey),
      encryptedRootFolderKey: bytesToHex(encrypted.encryptedRootFolderKey),
      encryptedRootIpnsPrivateKey: bytesToHex(encrypted.encryptedIpnsPrivateKey),
      rootIpnsName,
    }),
  });
  if (!initRes.ok) {
    throw new Error(`vault/init failed (${initRes.status}): ${await initRes.text()}`);
  }

  // 4. Configure API client singleton
  setApiClientConfig({
    baseUrl: apiUrl,
    getAccessToken: async () => accessToken,
  });

  // 5. Create and configure CipherBoxClient
  const client = new CipherBoxClient({
    apiUrl,
    getAccessToken: async () => accessToken,
    vaultKeypair: { publicKey, privateKey },
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
  });
  client.registerFolder(rootIpnsName, vault.rootFolderKey, vault.rootIpnsKeypair, [], 0n);

  return {
    client,
    accessToken,
    publicKey,
    privateKey,
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
    rootIpnsKeypair: vault.rootIpnsKeypair,
    email,
  };
}

/**
 * Create a fully-initialized test context (convenience wrapper over createTestAccount).
 */
export async function createTestContext(label: string): Promise<TestContext> {
  const account = await createTestAccount({ label });
  return { ...account, cleanup: () => account.client.destroy() };
}

/**
 * Delete a test account (cleanup after tests).
 */
export async function deleteTestAccount(
  ctx: { accessToken: string },
  apiUrl = API_URL
): Promise<void> {
  try {
    const res = await fetch(`${apiUrl}/auth/account`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${ctx.accessToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ confirmation: 'DELETE' }),
    });
    if (!res.ok) {
      console.warn(`Account deletion failed (${res.status}): ${await res.text()}`);
    }
  } catch (err) {
    console.warn(`Account deletion error: ${(err as Error).message}`);
  }
}

export { API_URL, SECRET };
