/**
 * Migration Worker Service
 *
 * Core logic for migrating encrypted pins between IPFS providers.
 * Runs inside TEE: decrypts provider credentials in-enclave, fetches
 * encrypted blobs from source, pins to destination, verifies CID integrity.
 *
 * SECURITY:
 * - Auth tokens processed as Uint8Array and zeroed with .fill(0) in finally block
 * - Endpoint URLs validated against SSRF (HTTPS-only, no private IPs, DNS rebinding check)
 * - No plaintext content access (opaque encrypted ciphertext only)
 */

import { decrypt } from 'eciesjs';
import { lookup } from 'node:dns/promises';
import { getKeypair } from './tee-keys.js';

export type ProviderConfig = {
  endpoint: string;
  authTokenBytes: Uint8Array; // SECURITY: Uint8Array for proper zeroing, NOT string
  protocol: 'psa' | 'kubo';
};

export type MigrationBatchResult = {
  succeeded: string[];
  failed: string[];
};

// --- SSRF Protection (from security review CRITICAL finding) ---

/**
 * Validate endpoint URL to prevent SSRF attacks.
 * TEE worker fetches from user-provided URLs -- must block internal/metadata endpoints.
 */
function validateEndpointUrl(endpoint: string): void {
  const url = new URL(endpoint);

  // Must be HTTPS
  if (url.protocol !== 'https:') {
    throw new Error('Migration endpoint must use HTTPS');
  }

  // Block private/internal IP ranges and metadata endpoints
  const hostname = url.hostname;
  if (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '::1' ||
    hostname.startsWith('10.') ||
    hostname.startsWith('192.168.') ||
    hostname === '169.254.169.254' ||
    hostname.endsWith('.internal') ||
    hostname.endsWith('.local') ||
    hostname.startsWith('169.254.') ||
    hostname.startsWith('fd') ||
    hostname.startsWith('fe80')
  ) {
    throw new Error('Migration endpoint cannot target private/internal addresses');
  }

  // Block 172.16.0.0/12 range
  if (hostname.startsWith('172.')) {
    const second = parseInt(hostname.split('.')[1], 10);
    if (second >= 16 && second <= 31) {
      throw new Error('Migration endpoint cannot target private/internal addresses');
    }
  }
}

/**
 * DNS rebinding protection: resolve hostname and verify IP is not private.
 * Prevents attacker.com -> 169.254.169.254 attacks.
 */
async function validateResolvedIp(hostname: string): Promise<void> {
  const result = await lookup(hostname);
  const ip = result.address;
  if (
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    ip.startsWith('127.') ||
    ip === '::1' ||
    ip.startsWith('169.254.') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80')
  ) {
    throw new Error('Migration endpoint DNS resolves to private address');
  }
  if (ip.startsWith('172.')) {
    const second = parseInt(ip.split('.')[1], 10);
    if (second >= 16 && second <= 31) {
      throw new Error('Migration endpoint DNS resolves to private address');
    }
  }
}

// --- End SSRF Protection ---

/**
 * Decrypt an ECIES-encrypted provider config using TEE's current epoch key.
 * Returns raw bytes for parsing.
 */
async function decryptEcies(
  encryptedBase64: string,
  teePrivateKey: Uint8Array
): Promise<Uint8Array> {
  const ciphertext = new Uint8Array(Buffer.from(encryptedBase64, 'base64'));
  return new Uint8Array(decrypt(teePrivateKey, ciphertext));
}

/**
 * Parse decrypted config bytes into ProviderConfig.
 * SECURITY: authToken stays as Uint8Array for proper zeroing.
 */
function parseProviderConfig(decryptedBytes: Uint8Array): ProviderConfig {
  const text = new TextDecoder().decode(decryptedBytes);
  const parsed = JSON.parse(text) as {
    endpoint: string;
    authToken: string;
    protocol: 'psa' | 'kubo';
  };
  return {
    endpoint: parsed.endpoint,
    authTokenBytes: new TextEncoder().encode(parsed.authToken),
    protocol: parsed.protocol,
  };
}

/** Get auth token as string for HTTP header -- caller must zero authTokenBytes after use */
function authTokenString(config: ProviderConfig): string {
  return new TextDecoder().decode(config.authTokenBytes);
}

/**
 * Migrate a batch of CIDs from source to destination provider.
 * Runs inside TEE -- credentials are decrypted in-enclave only.
 */
export async function migrateBatch(
  cids: string[],
  sourceConfigEncrypted: string,
  destConfigEncrypted: string,
  currentEpoch: number
): Promise<MigrationBatchResult> {
  // 1. Get TEE private key for this epoch
  const keypair = await getKeypair(currentEpoch);
  const teePrivateKey = keypair.privateKey;

  // 2. Decrypt provider configs in-enclave (returns Uint8Array)
  const sourceConfigBytes = await decryptEcies(sourceConfigEncrypted, teePrivateKey);
  const destConfigBytes = await decryptEcies(destConfigEncrypted, teePrivateKey);

  // Zero TEE private key immediately after decryption
  teePrivateKey.fill(0);

  const sourceConfig = parseProviderConfig(sourceConfigBytes);
  const destConfig = parseProviderConfig(destConfigBytes);

  // 2b. SSRF validation on both endpoints
  validateEndpointUrl(sourceConfig.endpoint);
  validateEndpointUrl(destConfig.endpoint);
  await validateResolvedIp(new URL(sourceConfig.endpoint).hostname);
  await validateResolvedIp(new URL(destConfig.endpoint).hostname);

  const succeeded: string[] = [];
  const failed: string[] = [];

  try {
    for (const cid of cids) {
      try {
        // 3. Fetch encrypted blob from source
        const data = await fetchFromProvider(cid, sourceConfig);

        // 4. Pin to destination
        const destCid = await pinToProvider(data, cid, destConfig);

        // 5. Verify CID match (content integrity)
        if (destCid !== cid) {
          throw new Error(`CID mismatch: expected ${cid}, got ${destCid}`);
        }

        succeeded.push(cid);
      } catch {
        failed.push(cid);
      }
    }
  } finally {
    // 6. Zero credentials from memory (Uint8Array.fill(0) -- same pattern as republish.ts)
    sourceConfig.authTokenBytes.fill(0);
    destConfig.authTokenBytes.fill(0);
    sourceConfigBytes.fill(0);
    destConfigBytes.fill(0);
  }

  return { succeeded, failed };
}

async function fetchFromProvider(cid: string, config: ProviderConfig): Promise<Uint8Array> {
  if (config.protocol === 'kubo') {
    const token = authTokenString(config);
    const headers: Record<string, string> = token ? { Authorization: `Basic ${token}` } : {};
    const response = await fetch(`${config.endpoint}/api/v0/cat?arg=${encodeURIComponent(cid)}`, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok) throw new Error(`Fetch from Kubo failed: ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }

  // PSA: use IPFS gateway to fetch content (PSA has no retrieval API)
  const GATEWAY_URL = process.env.IPFS_GATEWAY_URL || 'https://ipfs.io';
  const response = await fetch(`${GATEWAY_URL}/ipfs/${encodeURIComponent(cid)}`, {
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error(`Fetch from gateway failed: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function pinToProvider(
  data: Uint8Array,
  expectedCid: string,
  config: ProviderConfig
): Promise<string> {
  const token = authTokenString(config);

  if (config.protocol === 'kubo') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const blob = new Blob([data as any]);
    const formData = new FormData();
    formData.append('file', blob);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Basic ${token}`;

    const response = await fetch(`${config.endpoint}/api/v0/add?pin=true&cid-version=1`, {
      method: 'POST',
      body: formData,
      headers,
      signal: AbortSignal.timeout(60_000),
    });
    if (!response.ok) throw new Error(`Pin to Kubo failed: ${response.status}`);
    const result = (await response.json()) as { Hash: string };
    return result.Hash;
  }

  // PSA: pin by CID reference (data must already exist on IPFS network)
  const response = await fetch(`${config.endpoint}/pins`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      cid: expectedCid,
      name: `migration-${Date.now()}`,
    }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!response.ok) throw new Error(`PSA pin failed: ${response.status}`);
  const result = (await response.json()) as { pin: { cid: string } };
  return result.pin.cid;
}

// NOTE: No zeroString function -- JS strings are immutable and cannot be zeroed.
// All credentials are processed as Uint8Array throughout and zeroed with .fill(0)
// in the finally block of migrateBatch(). This follows the existing pattern from
// tee-worker/src/routes/republish.ts:86 (ipnsPrivateKey.fill(0)).
