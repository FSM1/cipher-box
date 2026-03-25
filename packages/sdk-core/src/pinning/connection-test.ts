import type { ConnectionTestResult } from './types';

/** Timeout for each connection probe (10 seconds) */
const PROBE_TIMEOUT_MS = 10_000;

/**
 * Test connection to an IPFS endpoint and auto-detect the protocol.
 *
 * Sequential probe strategy:
 * 1. Try Kubo RPC: POST /api/v0/id (skipped if endpoint contains pinata.cloud)
 * 2. Try Pinata: GET /data/testAuthentication
 * 3. Try PSA: GET /pins?limit=1
 *
 * Detects CORS errors and provides protocol-specific remediation instructions.
 */
export async function testConnection(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult> {
  const normalizedEndpoint = endpoint.replace(/\/+$/, '');
  const isPinataUrl = normalizedEndpoint.toLowerCase().includes('pinata.cloud');

  if (isPinataUrl) {
    // Pinata URL detected -- try Pinata probe first (skip Kubo)
    const pinataResult = await probePinata(normalizedEndpoint, authToken);
    if (pinataResult) return pinataResult;
  } else {
    // --- Probe 1: Kubo RPC ---
    const kuboResult = await probeKubo(normalizedEndpoint, authToken);
    if (kuboResult) return kuboResult;

    // --- Probe 2: Pinata ---
    const pinataResult = await probePinata(normalizedEndpoint, authToken);
    if (pinataResult) return pinataResult;
  }

  // --- Probe 3: PSA ---
  const psaResult = await probePsa(normalizedEndpoint, authToken);
  if (psaResult) return psaResult;

  // No protocol detected
  return {
    success: false,
    latencyMs: 0,
    error: 'could not detect ipfs protocol at this endpoint.',
  };
}

/** Probe Kubo RPC endpoint via POST /api/v0/id */
async function probeKubo(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult | null> {
  const url = `${endpoint}/api/v0/id`;
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Basic ${authToken}`;
  }

  const start = performance.now();

  try {
    const response = await fetch(url, {
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

    if (isCorsError(err)) {
      return {
        success: false,
        latencyMs,
        corsError: true,
        corsInstructions: kuboCorsInstructions(endpoint),
        error: 'CORS error: browser blocked the request. configure cors on your kubo node.',
      };
    }

    if (isTimeoutError(err)) {
      return {
        success: false,
        latencyMs,
        error: 'connection timed out after 10 seconds.',
      };
    }

    // Other errors (e.g., DNS failure, network down) -- try PSA
    return null;
  }
}

/** Probe Pinata API via GET /data/testAuthentication */
async function probePinata(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult | null> {
  const url = `${endpoint}/data/testAuthentication`;
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const start = performance.now();

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers,
      signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
    });

    const latencyMs = Math.round(performance.now() - start);

    if (response.ok) {
      return {
        success: true,
        protocol: 'pinata',
        version: 'Pinata API v3',
        latencyMs,
      };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        success: false,
        protocol: 'pinata',
        latencyMs,
        error: 'authentication failed. check your pinata jwt token.',
      };
    }

    return null;
  } catch (err) {
    const latencyMs = Math.round(performance.now() - start);

    if (isCorsError(err)) {
      return {
        success: false,
        latencyMs,
        corsError: true,
        corsInstructions:
          'pinata api should support browser requests. check if your jwt token has the correct permissions.',
        error: 'CORS error when connecting to pinata.',
      };
    }

    return null;
  }
}

/** Probe PSA endpoint via GET /pins?limit=1 */
async function probePsa(
  endpoint: string,
  authToken?: string
): Promise<ConnectionTestResult | null> {
  const url = `${endpoint}/pins?limit=1`;
  const headers: Record<string, string> = {};
  if (authToken) {
    headers['Authorization'] = `Bearer ${authToken}`;
  }

  const start = performance.now();

  try {
    const response = await fetch(url, {
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

    if (isCorsError(err)) {
      return {
        success: false,
        latencyMs,
        corsError: true,
        corsInstructions: psaCorsInstructions(),
        error: 'CORS error: browser blocked the request. check your pinning service cors settings.',
      };
    }

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

/**
 * Detect CORS errors from fetch.
 * Browsers throw TypeError with specific messages when CORS blocks a request.
 */
function isCorsError(err: unknown): boolean {
  if (!(err instanceof TypeError)) return false;
  const message = err.message.toLowerCase();
  return (
    message.includes('failed to fetch') ||
    message.includes('networkerror') ||
    message.includes('network request failed')
  );
}

/** Detect AbortSignal timeout errors */
function isTimeoutError(err: unknown): boolean {
  return err instanceof DOMException && err.name === 'AbortError';
}

/** CORS configuration instructions for Kubo nodes */
function kuboCorsInstructions(endpoint: string): string {
  void endpoint; // endpoint available for future per-node instructions
  return [
    'Configure CORS on your Kubo node:',
    '',
    `ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["https://app.cipherbox.cc", "http://localhost:5173"]'`,
    `ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["POST"]'`,
    `ipfs config --json API.HTTPHeaders.Access-Control-Allow-Headers '["Authorization", "Content-Type"]'`,
    '',
    'Then restart your Kubo node.',
  ].join('\n');
}

/** CORS configuration instructions for PSA services */
function psaCorsInstructions(): string {
  return 'check your pinning service dashboard for cors/allowed-origins settings. add https://app.cipherbox.cc to the allowed origins list.';
}
