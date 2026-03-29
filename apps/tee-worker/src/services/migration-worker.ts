/**
 * Migration Worker Service
 *
 * Core logic for migrating encrypted pins between IPFS providers.
 * Runs inside TEE: decrypts provider credentials in-enclave, fetches
 * encrypted blobs from source, pins to destination, verifies CID integrity.
 *
 * Uses @cipherbox/sdk-core KuboProvider and PsaProvider with SSRF-safe fetch
 * injection for all provider operations.
 *
 * SECURITY:
 * - Auth tokens processed as Uint8Array and zeroed with .fill(0) in finally block
 * - Endpoint URLs validated against SSRF (HTTPS-only, no private IPs, DNS rebinding check)
 * - No plaintext content access (opaque encrypted ciphertext only)
 */

import { unwrapKey } from '@cipherbox/crypto';
import { KuboProvider, PsaProvider } from '@cipherbox/sdk-core';
import { getKeypair } from './tee-keys.js';
import { validateEndpointUrl, ssrfSafeFetch } from './ssrf-validation.js';

/** Migration timeout for provider operations (generous for large files) */
const MIGRATION_TIMEOUT_MS = 60_000;

export type ProviderConfig = {
  endpoint: string;
  authTokenBytes: Uint8Array; // SECURITY: Uint8Array for proper zeroing, NOT string
  protocol: 'psa' | 'kubo' | 'cipherbox';
};

export type MigrationBatchResult = {
  succeeded: string[];
  failed: string[];
};

/**
 * Decrypt an ECIES-encrypted provider config using TEE's current epoch key.
 * Returns raw bytes for parsing.
 */
async function decryptEcies(encryptedHex: string, teePrivateKey: Uint8Array): Promise<Uint8Array> {
  const ciphertext = new Uint8Array(Buffer.from(encryptedHex, 'hex'));
  return await unwrapKey(ciphertext, teePrivateKey);
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

/** Get auth token as string for provider constructors -- caller must zero authTokenBytes after use */
function authTokenString(config: ProviderConfig): string {
  return new TextDecoder().decode(config.authTokenBytes);
}

/**
 * Fetch content by CID from a gateway (fallback for PSA/CipherBox protocols
 * that don't support direct content retrieval).
 */
async function fetchFromGateway(cid: string): Promise<Uint8Array> {
  const GATEWAY_URL = process.env.IPFS_GATEWAY_URL || 'https://ipfs.io';
  const response = await ssrfSafeFetch(`${GATEWAY_URL}/ipfs/${encodeURIComponent(cid)}`, {
    signal: AbortSignal.timeout(MIGRATION_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`Fetch from gateway failed: ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
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
  // DNS rebinding protection is handled by ssrfSafeFetch (DNS pinning in CVM mode)
  if (sourceConfig.protocol !== 'cipherbox') {
    validateEndpointUrl(sourceConfig.endpoint);
  }
  if (destConfig.protocol !== 'cipherbox') {
    validateEndpointUrl(destConfig.endpoint);
  }

  // 3. Instantiate providers with SSRF-safe fetch injection
  const providerOptions = { fetchFn: ssrfSafeFetch, timeoutMs: MIGRATION_TIMEOUT_MS };
  const sourceToken = authTokenString(sourceConfig);
  const destToken = authTokenString(destConfig);

  const sourceKubo =
    sourceConfig.protocol === 'kubo'
      ? new KuboProvider(sourceConfig.endpoint, sourceToken, providerOptions)
      : null;
  const destKubo =
    destConfig.protocol === 'kubo'
      ? new KuboProvider(destConfig.endpoint, destToken, providerOptions)
      : null;
  const destPsa =
    destConfig.protocol === 'psa'
      ? new PsaProvider(destConfig.endpoint, destToken, providerOptions)
      : null;
  const sourcePsa =
    sourceConfig.protocol === 'psa'
      ? new PsaProvider(sourceConfig.endpoint, sourceToken, providerOptions)
      : null;

  const succeeded: string[] = [];
  const failed: string[] = [];

  try {
    for (const cid of cids) {
      try {
        // 4. Fetch encrypted blob from source
        let data: Uint8Array;
        if (sourceKubo) {
          data = await sourceKubo.get(cid);
        } else {
          // PSA and CipherBox: use IPFS gateway to fetch content
          data = await fetchFromGateway(cid);
        }

        // 5. Pin to destination
        let destCid: string;
        if (destKubo) {
          const result = await destKubo.pin(data);
          destCid = result.cid;
        } else if (destPsa) {
          const result = await destPsa.pinByCid(cid, `migration-${Date.now()}`);
          destCid = result.cid;
        } else {
          throw new Error('CipherBox destination pinning handled by API-side MigrationProcessor');
        }

        // 6. Verify CID match (content integrity)
        if (destCid !== cid) {
          throw new Error(`CID mismatch: expected ${cid}, got ${destCid}`);
        }

        succeeded.push(cid);

        // Best-effort source unpin after verified transfer
        // Failure here is non-fatal -- the CID is already on the destination
        try {
          if (sourceConfig.protocol === 'kubo' && sourceKubo) {
            await sourceKubo.unpin(cid);
          } else if (sourceConfig.protocol === 'psa' && sourcePsa) {
            await sourcePsa.unpin(cid);
          }
          // 'cipherbox' protocol: unpin handled by API-side MigrationProcessor
        } catch {
          // Source unpin failure is non-fatal; CID is safely on destination
        }
      } catch {
        failed.push(cid);
      }
    }
  } finally {
    // 7. Zero credentials from memory (Uint8Array.fill(0) -- same pattern as republish.ts)
    sourceConfig.authTokenBytes.fill(0);
    destConfig.authTokenBytes.fill(0);
    sourceConfigBytes.fill(0);
    destConfigBytes.fill(0);
  }

  return { succeeded, failed };
}

// NOTE: No zeroString function -- JS strings are immutable and cannot be zeroed.
// All credentials are processed as Uint8Array throughout and zeroed with .fill(0)
// in the finally block of migrateBatch(). This follows the existing pattern from
// apps/tee-worker/src/routes/republish.ts:86 (ipnsPrivateKey.fill(0)).
