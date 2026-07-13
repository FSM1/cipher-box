/**
 * SDK E2E Test Harness
 *
 * Creates authenticated CipherBoxClient instances backed by real API accounts.
 * Extracted from packages/sdk/src/__tests__/integration.test.ts pattern.
 *
 * Each call to createTestContext() creates a unique user via /auth/test-login,
 * initializes their vault, and returns a ready-to-use CipherBoxClient.
 */

import {
  CipherBoxClient,
  buildGrantRemintCallbacks,
  type RotationClientCallbacks,
  type OwnerReconcileTransport,
  type GrantRow,
} from '@cipherbox/sdk';
import { initializeVault } from '@cipherbox/core';
import { hexToBytes, bytesToHex, base64ToBytes } from '@cipherbox/crypto';
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

/** Shape of a sent-share row (SentShareResponseDto) as returned by GET /shares/sent. */
interface SentShareRow {
  shareId: string;
  recipientPublicKey: string;
  encryptedReadKey: string;
  rootNodeId: string;
  shareRootIpnsName: string;
  rootGeneration: string;
}

/**
 * Build the opt-in web-mirroring `rotationCallbacks` seam for a single account.
 *
 * Mirrors apps/web (`rotation-driver.service.ts` + `owner-reconcile.service.ts`)
 * but sources every grant op from THIS account's own API via `testFetch` +
 * `accessToken` (the api-client global singleton carries no per-account auth).
 *
 * `clientHolder` is late-bound: the callbacks only fire during later mutations,
 * so the CipherBoxClient is assigned into the holder AFTER construction.
 *
 * `resolveInlineGrantRemint` can be disabled at runtime via the
 * `E2E_DISABLE_INLINE_REMINT=1` env hook (defaults to enabled) — this lets the
 * suite prove the seam is a REAL gate by re-running with the seam removed and
 * confirming the re-mint assertion fails.
 */
function buildInlineGrantRemintCallbacks(
  apiUrl: string,
  accessToken: string,
  clientHolder: { client: CipherBoxClient | null }
): RotationClientCallbacks {
  const authHeaders = (extra: Record<string, string> = {}) =>
    fetchHeaders({ Authorization: `Bearer ${accessToken}`, ...extra });

  async function fetchSentShares(): Promise<SentShareRow[]> {
    const res = await testFetch(`${apiUrl}/shares/sent`, { headers: authHeaders() });
    if (!res.ok) {
      throw new Error(`GET /shares/sent failed (${res.status}): ${await res.text()}`);
    }
    const data = (await res.json()) as { shares: SentShareRow[] };
    return data.shares;
  }

  const listSentGrants = async (): Promise<GrantRow[]> => {
    const shares = await fetchSentShares();
    return shares.map((s) => ({
      shareId: s.shareId,
      recipientPublicKey: hexToBytes(
        s.recipientPublicKey.startsWith('0x') ? s.recipientPublicKey.slice(2) : s.recipientPublicKey
      ),
      isRevoked: false,
      rootNodeId: s.rootNodeId,
    }));
  };

  const updateGrant = async (
    shareId: string,
    encryptedReadKey: string,
    generation: number
  ): Promise<void> => {
    // sdk-core `reMintGrantsRootedAt` hands `encryptedReadKey` as BASE64
    // (engine.ts:648 bytesToBase64), but PATCH /shares/:id/grant requires even-
    // length HEX (like the share-create DTO + the SDK's own share-create path).
    // This mismatch (a genuine product bug that also affects the web
    // owner-reconcile path) makes every re-mint PATCH 400. The `E2E_REMINT_HEX=1`
    // opt-in converts base64→hex so the file-share-rotation-remint reproduction
    // can reach the deeper file-key gap. It is a DIAGNOSTIC, not a fix, and
    // defaults OFF so the harness stays a faithful mirror of web.
    const encHex =
      process.env.E2E_REMINT_HEX === '1'
        ? bytesToHex(base64ToBytes(encryptedReadKey))
        : encryptedReadKey;
    const res = await testFetch(`${apiUrl}/shares/${shareId}/grant`, {
      method: 'PATCH',
      headers: authHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify({ encryptedReadKey: encHex, rootGeneration: String(generation) }),
    });
    if (!res.ok) {
      throw new Error(`PATCH /shares/${shareId}/grant failed (${res.status}): ${await res.text()}`);
    }
  };

  const deleteGrant = async (shareId: string): Promise<void> => {
    const res = await testFetch(`${apiUrl}/shares/${shareId}`, {
      method: 'DELETE',
      headers: authHeaders(),
    });
    if (!res.ok && res.status !== 204) {
      throw new Error(`DELETE /shares/${shareId} failed (${res.status}): ${await res.text()}`);
    }
  };

  return {
    getActiveGrantRootIpnsNames: async () => {
      const shares = await fetchSentShares();
      return new Set(shares.map((s) => s.shareRootIpnsName));
    },
    getLocalGrantRecord: () => null,
    persistJob: () => {},
    resolveInlineGrantRemint: async (_rootNodeIpnsName: string, _rootNodeId: string) => {
      const shares = await fetchSentShares();
      if (shares.length === 0) return undefined;

      // nodeId -> shareRootIpnsName, so the per-node getRecipientPubkeyPins seam
      // resolves the right node's owner-sealed pins during the rotation walk.
      const nodeIdToIpnsName = new Map<string, string>();
      for (const s of shares) {
        if (!nodeIdToIpnsName.has(s.rootNodeId)) {
          nodeIdToIpnsName.set(s.rootNodeId, s.shareRootIpnsName);
        }
      }

      const grants = await listSentGrants();

      const transport: OwnerReconcileTransport = {
        listSentGrants,
        updateGrant,
        deleteGrant,
        getRecipientPubkeyPins: (nodeId: string) => {
          const ipnsName = nodeIdToIpnsName.get(nodeId);
          if (!ipnsName) {
            throw new Error(
              `resolveInlineGrantRemint: no share-root IPNS name for node ${nodeId} — refusing to re-mint (fail-closed)`
            );
          }
          const client = clientHolder.client;
          if (!client) throw new Error('resolveInlineGrantRemint: client not initialized');
          return client.getRecipientPubkeyPins(ipnsName);
        },
      };

      return {
        innerGrants: grants,
        grantCallbacks: buildGrantRemintCallbacks(transport),
      };
    },
  };
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
  /**
   * Opt-in: wire this account's CipherBoxClient with a `rotationCallbacks` seam
   * that mirrors apps/web (rotation-driver + owner-reconcile) but sourced from
   * THIS account's own API via `testFetch` + its `accessToken` (never the
   * api-client global singleton — that carries no per-account auth). When false
   * (default) no `rotationCallbacks` is passed and the client behaves exactly as
   * every other suite's client (zero rotation). Used to prove the web
   * file-share grant re-mint on scope-exit rotation (recipient-pin-lifecycle §5).
   */
  withInlineGrantRemint?: boolean;
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

    // 6a. Opt-in rotation seam (recipient-pin-lifecycle §5): build the
    // web-mirroring rotationCallbacks BEFORE constructing the client (the
    // callbacks close over a late-bound clientHolder, assigned after
    // construction). The RED test hook `E2E_DISABLE_INLINE_REMINT=1` strips the
    // inline seam to prove it is a real gate; every other callback stays wired so
    // scope-exit rotation still triggers (getActiveGrantRootIpnsNames), matching
    // the pre-fix sweep-only web behavior.
    const clientHolder: { client: CipherBoxClient | null } = { client: null };
    let rotationCallbacks: RotationClientCallbacks | undefined;
    if (opts.withInlineGrantRemint) {
      rotationCallbacks = buildInlineGrantRemintCallbacks(apiUrl, accessToken, clientHolder);
      if (process.env.E2E_DISABLE_INLINE_REMINT === '1') {
        rotationCallbacks.resolveInlineGrantRemint = undefined;
      }
    }

    // 6. Create CipherBoxClient with instance-scoped axios (no singleton needed).
    // rootWriteKey + rootIpnsKeypair mirror the web host-layer wiring (68.1-03,
    // useAuth.ts) so ensureFolderLoaded / recoverWriteKeyIfNeeded can
    // self-bootstrap write-capable folder state from root (DFS descent).
    // The constructor makes defensive copies of all key buffers (D-09).
    const client = new CipherBoxClient({
      apiUrl,
      getAccessToken: async () => accessToken,
      vaultKeypair: { publicKey, privateKey },
      rootIpnsName,
      rootFolderKey: vault.rootReadKey,
      rootWriteKey: vault.rootWriteKey,
      rootIpnsKeypair: vault.rootIpnsKeypair,
      defaultHeaders: axiosDefaultHeaders(),
      ...(rotationCallbacks ? { rotationCallbacks } : {}),
    });
    // Late-bind the client into the holder so the rotationCallbacks (which only
    // fire during later mutations) can reach getRecipientPubkeyPins.
    clientHolder.client = client;
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
export async function createTestContext(
  label: string,
  opts?: { withInlineGrantRemint?: boolean }
): Promise<TestContext> {
  const account = await createTestAccount({ label, ...opts });
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
