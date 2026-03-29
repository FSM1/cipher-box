/**
 * Connection Test Route
 *
 * POST /connection-test - Server-side IPFS endpoint connection test.
 *
 * Receives ECIES-encrypted provider config (endpoint + authToken),
 * decrypts in-enclave, probes the endpoint for Kubo RPC or PSA protocol,
 * and returns the result. Avoids browser CORS issues since the probe
 * runs server-side.
 *
 * SECURITY:
 * - Provider credentials decrypted only inside TEE
 * - Auth token bytes zeroed after probing completes
 * - SSRF protection on user-provided endpoint URLs
 * - TEE private key zeroed immediately after decryption
 */

import { Router, type Request, type Response } from 'express';
import { unwrapKey } from '@cipherbox/crypto';
import { getKeypair } from '../services/tee-keys.js';
import {
  validateEndpointUrl,
  validateResolvedIp,
  ssrfSafeFetch,
} from '../services/ssrf-validation.js';

/** Timeout for each connection probe (10 seconds) */
const PROBE_TIMEOUT_MS = 10_000;

const router = Router();

router.post('/connection-test', async (req: Request, res: Response) => {
  const { encryptedConfig, epoch } = req.body as {
    encryptedConfig?: string;
    epoch?: number;
  };

  if (!encryptedConfig || epoch === undefined || epoch === null) {
    res.status(400).json({
      success: false,
      latencyMs: 0,
      error: 'Missing required fields: encryptedConfig, epoch',
    });
    return;
  }

  let configBytes: Uint8Array | null = null;
  let tokenBytes: Uint8Array | null = null;

  try {
    // 1. Get TEE keypair for this epoch
    const keypair = await getKeypair(epoch);

    // 2. Decrypt ECIES-encrypted config in-enclave
    const ciphertext = new Uint8Array(Buffer.from(encryptedConfig, 'hex'));
    configBytes = await unwrapKey(ciphertext, keypair.privateKey);

    // 3. Zero TEE private key immediately
    keypair.privateKey.fill(0);

    // 4. Parse config
    const configText = new TextDecoder().decode(configBytes);
    const { endpoint, authToken } = JSON.parse(configText) as {
      endpoint: string;
      authToken?: string;
    };

    // 5. Create Uint8Array copy of auth token for zeroing
    tokenBytes = new TextEncoder().encode(authToken ?? '');

    // 6. Normalize endpoint
    const normalizedEndpoint = endpoint.replace(/\/+$/, '');

    // 7. SSRF validation (skipped in simulator mode)
    validateEndpointUrl(normalizedEndpoint);
    if (process.env.TEE_MODE !== 'simulator') {
      await validateResolvedIp(new URL(normalizedEndpoint).hostname);
    }

    // 8. Sequential probe: Kubo first, then PSA
    const kuboResult = await probeKubo(normalizedEndpoint, authToken);
    if (kuboResult) {
      res.status(200).json(kuboResult);
      return;
    }

    const psaResult = await probePsa(normalizedEndpoint, authToken);
    if (psaResult) {
      res.status(200).json(psaResult);
      return;
    }

    // Neither protocol detected
    res.status(200).json({
      success: false,
      latencyMs: 0,
      error: 'could not detect ipfs protocol at this endpoint.',
    });
  } catch (err) {
    console.error('Connection test failed:', err instanceof Error ? err.message : 'Unknown error');
    res.status(200).json({
      success: false,
      latencyMs: 0,
      error: err instanceof Error ? err.message : 'Connection test failed',
    });
  } finally {
    // Zero sensitive data
    if (configBytes) configBytes.fill(0);
    if (tokenBytes) tokenBytes.fill(0);
  }
});

/** Probe Kubo RPC endpoint via POST /api/v0/id */
async function probeKubo(
  endpoint: string,
  authToken?: string
): Promise<{
  success: boolean;
  protocol?: string;
  version?: string;
  latencyMs: number;
  error?: string;
} | null> {
  const url = `${endpoint}/api/v0/id`;
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Basic ${authToken}`;
  }

  const start = performance.now();

  try {
    const response = await ssrfSafeFetch(url, {
      method: 'POST',
      headers,
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });

    const latencyMs = Math.round(performance.now() - start);

    if (response.ok) {
      const data = (await response.json()) as { AgentVersion?: string };
      return {
        success: true,
        protocol: 'kubo',
        version: data.AgentVersion,
        latencyMs,
      };
    }

    // 401/403/422 means the endpoint exists and speaks Kubo, but auth failed
    if (response.status === 401 || response.status === 403 || response.status === 422) {
      return {
        success: false,
        protocol: 'kubo',
        latencyMs,
        error: 'authentication failed. check your auth token.',
      };
    }

    // Other non-200 -- not Kubo, try PSA
    return null;
  } catch (err) {
    const latencyMs = Math.round(performance.now() - start);

    if (isTimeoutError(err)) {
      return {
        success: false,
        latencyMs,
        error: 'connection timed out after 10 seconds.',
      };
    }

    // Other errors (DNS failure, network down) -- try PSA
    return null;
  }
}

/** Probe PSA endpoint via GET /pins?limit=1 */
async function probePsa(
  endpoint: string,
  authToken?: string
): Promise<{ success: boolean; protocol?: string; latencyMs: number; error?: string } | null> {
  const url = `${endpoint}/pins?limit=1`;
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const start = performance.now();

  try {
    const response = await ssrfSafeFetch(url, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });

    const latencyMs = Math.round(performance.now() - start);

    if (response.ok) {
      return {
        success: true,
        protocol: 'psa',
        latencyMs,
      };
    }

    if (response.status === 401 || response.status === 403 || response.status === 422) {
      return {
        success: false,
        protocol: 'psa',
        latencyMs,
        error: 'authentication failed. check your auth token.',
      };
    }

    // Other non-200 status -- not recognizable as PSA
    return null;
  } catch (err) {
    const latencyMs = Math.round(performance.now() - start);

    if (isTimeoutError(err)) {
      return {
        success: false,
        latencyMs,
        error: 'connection timed out after 10 seconds.',
      };
    }

    // Other errors
    return null;
  }
}

/** Detect AbortSignal timeout errors (Node.js style) */
function isTimeoutError(err: unknown): boolean {
  if (err instanceof Error && err.name === 'AbortError') return true;
  // Node.js 20+ uses TimeoutError
  if (err instanceof Error && err.name === 'TimeoutError') return true;
  return false;
}

export default router;
