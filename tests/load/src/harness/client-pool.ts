/**
 * Load Test Client Pool
 *
 * Manages N CipherBoxClient instances, each with its own test account.
 * Creates accounts in parallel, distributes workloads, and collects metrics.
 */

import { CipherBoxClient } from '@cipherbox/sdk';
import { setApiClientConfig } from '@cipherbox/api-client';
import { initializeVault, encryptVaultKeys } from '@cipherbox/core';
import { deriveIpnsName, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { MetricsCollector } from './metrics';

const API_URL = process.env.LOAD_TEST_API_URL ?? 'http://localhost:3000';
const SECRET = process.env.LOAD_TEST_SECRET ?? 'e2e-test-secret-do-not-use-in-production';

export interface PoolClient {
  id: number;
  client: CipherBoxClient;
  accessToken: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
  rootIpnsName: string;
  rootFolderKey: Uint8Array;
  rootIpnsKeypair: { publicKey: Uint8Array; privateKey: Uint8Array };
  metrics: MetricsCollector;
}

export interface ClientPoolOptions {
  clientCount: number;
  label: string;
}

/**
 * Create a pool of N authenticated CipherBoxClient instances.
 *
 * Each client has its own test account, vault, and metrics collector.
 * The api-client singleton is configured once (all clients share baseUrl,
 * tokens are per-request via getAccessToken closure).
 */
export async function createClientPool(opts: ClientPoolOptions): Promise<PoolClient[]> {
  const { clientCount, label } = opts;
  console.log(`Creating ${clientCount} test accounts for "${label}"...`);
  const start = performance.now();

  // Create accounts in parallel batches of 5 to avoid overwhelming the API
  const clients: PoolClient[] = [];
  const batchSize = 5;

  for (let batch = 0; batch < clientCount; batch += batchSize) {
    const batchEnd = Math.min(batch + batchSize, clientCount);
    const promises = [];

    for (let i = batch; i < batchEnd; i++) {
      promises.push(createPoolClient(i, label));
    }

    const results = await Promise.allSettled(promises);
    for (const result of results) {
      if (result.status === 'fulfilled') {
        clients.push(result.value);
      } else {
        console.warn(`Failed to create pool client: ${result.reason}`);
      }
    }
  }

  // Configure the singleton once — all clients share the same baseUrl
  // Individual tokens are injected via the getAccessToken closure on each client
  if (clients.length > 0) {
    setApiClientConfig({
      baseUrl: API_URL,
      getAccessToken: async () => clients[0].accessToken,
    });
  }

  const elapsed = performance.now() - start;
  console.log(
    `Created ${clients.length}/${clientCount} clients in ${(elapsed / 1000).toFixed(1)}s`
  );

  return clients;
}

async function createPoolClient(id: number, label: string): Promise<PoolClient> {
  const email = `load-${label}-${id}-${Date.now()}@example.com`;

  // 1. Authenticate
  const loginRes = await fetch(`${API_URL}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret: SECRET }),
  });
  if (!loginRes.ok) {
    throw new Error(`test-login failed for client ${id}: ${loginRes.status}`);
  }
  const { accessToken, publicKeyHex, privateKeyHex } = await loginRes.json();
  const publicKey = hexToBytes(publicKeyHex);
  const privateKey = hexToBytes(privateKeyHex);

  // 2. Initialize vault
  const vault = await initializeVault(privateKey);
  const encrypted = await encryptVaultKeys(vault, publicKey);
  const rootIpnsName = await deriveIpnsName(vault.rootIpnsKeypair.publicKey);

  // 3. Register vault
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
    throw new Error(`vault/init failed for client ${id}: ${initRes.status}`);
  }

  // 4. Create CipherBoxClient
  const client = new CipherBoxClient({
    apiUrl: API_URL,
    getAccessToken: async () => accessToken,
    vaultKeypair: { publicKey, privateKey },
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
  });
  client.registerFolder(rootIpnsName, vault.rootFolderKey, vault.rootIpnsKeypair, [], 0n);

  return {
    id,
    client,
    accessToken,
    publicKey,
    privateKey,
    rootIpnsName,
    rootFolderKey: vault.rootFolderKey,
    rootIpnsKeypair: vault.rootIpnsKeypair,
    metrics: new MetricsCollector(),
  };
}

/**
 * Destroy all clients in the pool and delete test accounts.
 */
export async function destroyClientPool(pool: PoolClient[]): Promise<void> {
  console.log(`Cleaning up ${pool.length} test accounts...`);
  for (const pc of pool) {
    pc.client.destroy();
    try {
      await fetch(`${API_URL}/auth/account`, {
        method: 'DELETE',
        headers: {
          Authorization: `Bearer ${pc.accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ confirmation: 'DELETE' }),
      });
    } catch {
      // Best-effort cleanup
    }
  }
}
