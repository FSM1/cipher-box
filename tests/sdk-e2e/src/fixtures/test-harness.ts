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
import { initializeVault } from '@cipherbox/core';
import { hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { publishVaultKeyBlob, publishEmptyRootNode } from '@cipherbox/sdk-core';
import type { SdkContext } from '@cipherbox/sdk-core';
import { createAxiosInstance } from '@cipherbox/api-client';

const API_URL = process.env.SDK_E2E_API_URL ?? 'http://localhost:3000';
const SECRET = process.env.SDK_E2E_SECRET ?? 'e2e-test-secret-do-not-use-in-production';
const THROTTLE_BYPASS = process.env.THROTTLE_BYPASS_SECRET ?? '';

/**
 * Build default headers for fetch calls.
 * Includes the throttle bypass header when THROTTLE_BYPASS_SECRET is set.
 */
function fetchHeaders(extra: Record<string, string> = {}): Record<string, string> {
  const headers: Record<string, string> = { ...extra };
  if (THROTTLE_BYPASS) {
    headers['X-Throttle-Bypass'] = THROTTLE_BYPASS;
  }
  return headers;
}

/** Default headers for the api-client axios instance (throttle bypass). */
function axiosDefaultHeaders(): Record<string, string> | undefined {
  return THROTTLE_BYPASS ? { 'X-Throttle-Bypass': THROTTLE_BYPASS } : undefined;
}

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
  /**
   * UUID of the root Node published by publishEmptyRootNode (D-06). Threaded
   * into the client's folderTree via registerFolder so root-folder publishes
   * (e.g. uploadFile to the root) carry a stable nodeId instead of tripping
   * the registration.ts:221 "nodeId is required" guard.
   */
  rootNodeId: string;
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
    headers: fetchHeaders({ 'Content-Type': 'application/json' }),
    body: JSON.stringify({ email, secret }),
  });
  if (!loginRes.ok) {
    throw new Error(`test-login failed (${loginRes.status}): ${await loginRes.text()}`);
  }
  const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
  const publicKey = hexToBytes(publicKeyHex);
  const privateKey = hexToBytes(privateKeyHex);

  // Steps 2-5 wrapped in try/catch to clean up the test account on failure
  try {
    // 2. Initialize vault
    const vault = await initializeVault(privateKey);

    // 3. Publish vault key blob to IPNS (rootFolderKey storage for recovery)
    const axiosInstance = createAxiosInstance({
      baseUrl: apiUrl,
      getAccessToken: async () => accessToken,
      defaultHeaders: axiosDefaultHeaders(),
    });
    const sdkCtx: SdkContext = {
      apiUrl,
      getAccessToken: async () => accessToken,
      axiosInstance,
    };
    await publishVaultKeyBlob({
      userPrivateKey: privateKey,
      userPublicKey: publicKey,
      rootReadKey: vault.rootReadKey,
      rootWriteKey: vault.rootWriteKey,
      ctx: sdkCtx,
    });

    // 4. Publish a real, empty kind:'root' Node (D-06) mirroring the web
    // new-user flow (useAuth.ts -> publishEmptyRootNode). Derives+returns
    // rootIpnsName internally -- no separate deriveIpnsName call needed
    // (matches decision 68.1-03). No teeKeys: the harness has no TEE
    // enrollment, same as a brand-new user.
    const {
      ipnsName: rootIpnsName,
      nodeId: rootNodeId,
      sequenceNumber: rootSequenceNumber,
    } = await publishEmptyRootNode({
      rootIpnsKeypair: vault.rootIpnsKeypair,
      rootReadKey: vault.rootReadKey,
      rootWriteKey: vault.rootWriteKey,
      ctx: sdkCtx,
    });

    // 5. Register vault on server (v2: only ownerPublicKey + rootIpnsName, crypto lives in IPFS)
    const initRes = await fetch(`${apiUrl}/vault/init`, {
      method: 'POST',
      headers: fetchHeaders({
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
      }),
      body: JSON.stringify({
        ownerPublicKey: bytesToHex(publicKey),
        rootIpnsName,
      }),
    });
    if (!initRes.ok) {
      throw new Error(`vault/init failed (${initRes.status}): ${await initRes.text()}`);
    }

    // 6. Create CipherBoxClient with instance-scoped axios (no singleton needed)
    const client = new CipherBoxClient({
      apiUrl,
      getAccessToken: async () => accessToken,
      vaultKeypair: { publicKey, privateKey },
      rootIpnsName,
      rootFolderKey: vault.rootReadKey,
      defaultHeaders: axiosDefaultHeaders(),
    });
    // D-06: thread the published root Node's nodeId/nodeGeneration (0, first
    // publish) and rootWriteKey so subsequent publishes (e.g. uploadFile to
    // the root) don't trip registration.ts:221's "nodeId is required" guard.
    client.registerFolder(
      rootIpnsName,
      vault.rootReadKey,
      vault.rootIpnsKeypair,
      [],
      rootSequenceNumber,
      rootNodeId,
      0,
      vault.rootWriteKey
    );

    return {
      client,
      accessToken,
      publicKey,
      privateKey,
      rootIpnsName,
      rootFolderKey: vault.rootReadKey,
      rootIpnsKeypair: vault.rootIpnsKeypair,
      email,
      rootNodeId,
    };
  } catch (err) {
    // Clean up partially provisioned account to avoid leaks
    await deleteTestAccount({ accessToken }, apiUrl);
    throw err;
  }
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
      headers: fetchHeaders({
        Authorization: `Bearer ${ctx.accessToken}`,
        'Content-Type': 'application/json',
      }),
      body: JSON.stringify({ confirmation: 'DELETE' }),
    });
    if (!res.ok) {
      console.warn(`Account deletion failed (${res.status}): ${await res.text()}`);
    }
  } catch (err) {
    console.warn(`Account deletion error: ${(err as Error).message}`);
  }
}

/**
 * fetch() wrapper that automatically injects the throttle bypass header.
 * Use instead of raw fetch() in test suites to avoid 429s.
 */
export function testFetch(url: string, init?: RequestInit): Promise<Response> {
  const headers = new Headers(init?.headers);
  if (THROTTLE_BYPASS) {
    headers.set('X-Throttle-Bypass', THROTTLE_BYPASS);
  }
  return fetch(url, { ...init, headers });
}

export { API_URL, SECRET, fetchHeaders };
