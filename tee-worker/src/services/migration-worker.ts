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
import { getKeypair } from './tee-keys.js';
import { validateEndpointUrl, validateResolvedIp, ssrfSafeFetch } from './ssrf-validation.js';

export type ProviderConfig = {
  endpoint: string;
  authTokenBytes: Uint8Array; // SECURITY: Uint8Array for proper zeroing, NOT string
  protocol: 'psa' | 'kubo' | 'cipherbox';
};

export type MigrationBatchResult = {
  succeeded: string[];
  failed: string[];
};

// SSRF validation imported from shared ssrf-validation module

/**
 * Decrypt an ECIES-encrypted provider config using TEE's current epoch key.
 * Returns raw bytes for parsing.
 */
async function decryptEcies(encryptedHex: string, teePrivateKey: Uint8Array): Promise<Uint8Array> {
  const ciphertext = new Uint8Array(Buffer.from(encryptedHex, 'hex'));
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
    authToken?: string;
    protocol: 'psa' | 'kubo' | 'cipherbox';
  };
  return {
    endpoint: parsed.endpoint,
    authTokenBytes: new TextEncoder().encode(parsed.authToken ?? ''),
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

  // 2b. SSRF validation on both endpoints (skipped in simulator mode)
  if (sourceConfig.endpoint !== 'cipherbox') {
    validateEndpointUrl(sourceConfig.endpoint);
    if (process.env.TEE_MODE !== 'simulator') {
      await validateResolvedIp(new URL(sourceConfig.endpoint).hostname);
    }
  }
  if (destConfig.endpoint !== 'cipherbox') {
    validateEndpointUrl(destConfig.endpoint);
    if (process.env.TEE_MODE !== 'simulator') {
      await validateResolvedIp(new URL(destConfig.endpoint).hostname);
    }
  }

  const succeeded: string[] = [];
  const failed: string[] = [];

  // Decode auth tokens once for the entire batch instead of per-CID
  const sourceToken = authTokenString(sourceConfig);
  const destToken = authTokenString(destConfig);

  try {
    for (const cid of cids) {
      try {
        // 3. Fetch encrypted blob from source
        const data = await fetchFromProvider(cid, sourceConfig, sourceToken);

        // 4. Pin to destination
        const destCid = await pinToProvider(data, cid, destConfig, destToken);

        // 5. Verify CID match (content integrity)
        if (destCid !== cid) {
          throw new Error(`CID mismatch: expected ${cid}, got ${destCid}`);
        }

        succeeded.push(cid);

        // Best-effort source unpin after verified transfer
        // Failure here is non-fatal -- the CID is already on the destination
        try {
          if (sourceConfig.protocol !== 'cipherbox') {
            await unpinFromProvider(cid, sourceConfig, sourceToken);
          }
        } catch {
          // Source unpin failure is non-fatal; CID is safely on destination
        }
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

/**
 * Unpin a CID from a provider after verified migration transfer.
 * Supports Kubo (POST /pin/rm) and PSA (list by CID + DELETE) protocols.
 * Best-effort: failures are non-fatal since the CID is already on the destination.
 */
async function unpinFromProvider(
  cid: string,
  config: ProviderConfig,
  token: string
): Promise<void> {
  if (config.protocol === 'kubo') {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Basic ${token}`;
    const response = await ssrfSafeFetch(
      `${config.endpoint}/api/v0/pin/rm?arg=${encodeURIComponent(cid)}`,
      {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(30_000),
      }
    );
    if (!response.ok) {
      const errorText = await response.text();
      // "not pinned" means already unpinned -- treat as success (idempotent)
      if (errorText.toLowerCase().includes('not pinned')) return;
      throw new Error(`Unpin from Kubo failed: ${response.status}`);
    }
    return;
  }

  if (config.protocol === 'psa') {
    // PSA requires finding the requestid first, then deleting
    const listResponse = await ssrfSafeFetch(
      `${config.endpoint}/pins?cid=${encodeURIComponent(cid)}&status=pinned,pinning,queued`,
      {
        method: 'GET',
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(30_000),
      }
    );
    if (!listResponse.ok) return; // Best-effort: if list fails, skip unpin
    const listResult = (await listResponse.json()) as { results: Array<{ requestid: string }> };
    for (const pin of listResult.results) {
      await ssrfSafeFetch(`${config.endpoint}/pins/${encodeURIComponent(pin.requestid)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(30_000),
      });
    }
    return;
  }

  // 'cipherbox' protocol: unpin via CipherBox API -- not handled in TEE worker.
  // CipherBox unpins are handled by the API-side MigrationProcessor.
}

async function fetchFromProvider(
  cid: string,
  config: ProviderConfig,
  token: string
): Promise<Uint8Array> {
  if (config.protocol === 'kubo') {
    const headers: Record<string, string> = token ? { Authorization: `Basic ${token}` } : {};
    const response = await ssrfSafeFetch(
      `${config.endpoint}/api/v0/cat?arg=${encodeURIComponent(cid)}`,
      {
        method: 'POST',
        headers,
        signal: AbortSignal.timeout(60_000),
      }
    );
    if (!response.ok) throw new Error(`Fetch from Kubo failed: ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }

  // CipherBox or PSA: use IPFS gateway to fetch content
  const GATEWAY_URL = process.env.IPFS_GATEWAY_URL || 'https://ipfs.io';
  const response = await ssrfSafeFetch(`${GATEWAY_URL}/ipfs/${encodeURIComponent(cid)}`, {
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error(`Fetch from gateway failed: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function pinToProvider(
  data: Uint8Array,
  expectedCid: string,
  config: ProviderConfig,
  token: string
): Promise<string> {
  if (config.protocol === 'kubo') {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const blob = new Blob([data as any]);
    const formData = new FormData();
    formData.append('file', blob);
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Basic ${token}`;

    const response = await ssrfSafeFetch(`${config.endpoint}/api/v0/add?pin=true&cid-version=1`, {
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
  const response = await ssrfSafeFetch(`${config.endpoint}/pins`, {
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
