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

export interface TestContext {
  client: CipherBoxClient;
  accessToken: string;
  refreshToken: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  rootIpnsName: string;
  rootFolderKey: Uint8Array;
  rootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  email: string;
  /** Destroy the client and zero key material */
  cleanup: () => void;
}

/**
 * Create a fully-initialized test context with a new user account.
 *
 * Steps:
 * 1. POST /auth/test-login → accessToken + keypair
 * 2. initializeVault(privateKey) → rootFolderKey, rootIpnsKeypair
 * 3. encryptVaultKeys + POST /vault/init
 * 4. setApiClientConfig (singleton — see multi-account caveat)
 * 5. new CipherBoxClient + registerFolder
 */
export async function createTestContext(label: string): Promise<TestContext> {
  const email = `sdk-e2e-${label}-${Date.now()}@example.com`;

  // 1. Authenticate
  const loginRes = await fetch(`${API_URL}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret: SECRET }),
  });
  if (!loginRes.ok) {
    throw new Error(`test-login failed (${loginRes.status}): ${await loginRes.text()}`);
  }
  const { accessToken, refreshToken, publicKeyHex, privateKeyHex } = await loginRes.json();
  const publicKey = hexToBytes(publicKeyHex);
  const privateKey = hexToBytes(privateKeyHex);

  // 2. Initialize vault
  const vault = await initializeVault(privateKey);
  const encrypted = await encryptVaultKeys(vault, publicKey);
  const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

  // 3. Register vault on server
  const initRes = await fetch(`${API_URL}/vault/init`, {
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
    baseUrl: API_URL,
    getAccessToken: async () => accessToken,
  });

  // 5. Create and configure CipherBoxClient
  const client = new CipherBoxClient({
    apiUrl: API_URL,
    getAccessToken: async () => accessToken,
    vaultKeypair: { publicKey, privateKey },
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
  });
  client.registerFolder(rootIpnsName, vault.rootFolderKey, vault.rootIpnsKeypair, [], 0n);

  return {
    client,
    accessToken,
    refreshToken,
    publicKey,
    privateKey,
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
    rootIpnsKeypair: vault.rootIpnsKeypair,
    email,
    cleanup: () => client.destroy(),
  };
}

/**
 * Delete a test account (cleanup after tests).
 * Uses the access token from the test context.
 */
export async function deleteTestAccount(ctx: TestContext): Promise<void> {
  try {
    const res = await fetch(`${API_URL}/auth/account`, {
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
