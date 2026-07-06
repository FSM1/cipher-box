import { useCallback, useEffect, useState } from 'react';
import type { ConnectionTestResult } from '@cipherbox/sdk';
import { wrapKey, hexToBytes, bytesToHex } from '@cipherbox/crypto';
import { teeControllerConnectionTest } from '@cipherbox/api-client';
import { useAuthStore } from '../../stores/auth.store';
import { getSdkClient } from '../../lib/sdk-provider';
import { logger } from '../../lib/logger';

type ConnectionTestProps = {
  endpoint: string;
  authToken: string;
  onTestResult?: (result: ConnectionTestResult | null) => void;
};

/**
 * Connection test UI for BYO-IPFS node endpoint.
 *
 * Routes the connection test through the TEE worker to avoid browser CORS
 * issues. Provider credentials are ECIES-encrypted before leaving the browser
 * and decrypted only inside the TEE enclave for server-side probing.
 *
 * Falls back to browser-side testConnection() when TEE keys are unavailable.
 */
export function ConnectionTest({ endpoint, authToken, onTestResult }: ConnectionTestProps) {
  const [testResult, setTestResult] = useState<ConnectionTestResult | null>(null);
  const [isTesting, setIsTesting] = useState(false);

  // Clear result when endpoint or authToken changes
  useEffect(() => {
    setTestResult(null);
    onTestResult?.(null);
  }, [endpoint, authToken]); // onTestResult intentionally excluded -- only fire on input changes

  const handleTest = useCallback(async () => {
    if (!endpoint || isTesting) return;
    setIsTesting(true);
    setTestResult(null);
    onTestResult?.(null);

    try {
      // Try TEE-routed test first (avoids CORS, keeps credentials encrypted)
      const teeKeys = useAuthStore.getState().teeKeys;

      if (teeKeys?.currentPublicKey) {
        const result = await teeRoutedTest(endpoint, authToken, teeKeys);
        setTestResult(result);
        onTestResult?.(result);
      } else {
        // Fallback: browser-side test when TEE keys not available
        logger.warn('[BYO] TEE keys not available, falling back to browser-side connection test');
        const result = await getSdkClient().testConnection(endpoint, authToken || undefined);
        setTestResult(result);
        onTestResult?.(result);
      }
    } catch {
      const errorResult: ConnectionTestResult = {
        success: false,
        latencyMs: 0,
        error: 'connection test failed. please try again.',
      };
      setTestResult(errorResult);
      onTestResult?.(errorResult);
    } finally {
      setIsTesting(false);
    }
  }, [endpoint, authToken, isTesting, onTestResult]);

  return (
    <div className="connection-test">
      <button
        type="button"
        className="connection-test-btn"
        onClick={handleTest}
        disabled={isTesting || !endpoint}
      >
        {isTesting ? (
          <>
            {'[--testing...]'}
            <span className="connection-test-spinner" />
          </>
        ) : (
          '[--test connection]'
        )}
      </button>

      {testResult && (
        <div className="connection-test-result" role="status" aria-live="polite">
          {testResult.success ? (
            <div className="connection-test-success">
              {'> connected ('}
              {testResult.latencyMs}
              {'ms) // detected: '}
              {testResult.protocol}
              {testResult.version ? ` ${testResult.version}` : ''}
            </div>
          ) : (
            <div className="connection-test-error">
              {testResult.error?.includes('authentication') ? (
                <>{`> failed: authentication failed. check your auth token.`}</>
              ) : (
                <>
                  {`> failed: ${testResult.error || 'could not detect ipfs protocol at this endpoint.'}`}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/**
 * Run connection test via TEE worker (server-side, no CORS issues).
 *
 * 1. ECIES-encrypt { endpoint, authToken } with TEE public key
 * 2. POST encrypted config to /tee/connection-test
 * 3. TEE decrypts in-enclave, probes endpoint, returns result
 */
async function teeRoutedTest(
  endpoint: string,
  authToken: string,
  teeKeys: { currentPublicKey: string; currentEpoch: number }
): Promise<ConnectionTestResult> {
  // Build config JSON and ECIES-encrypt with TEE public key
  const configJson = JSON.stringify({ endpoint, authToken: authToken || undefined });
  const configBytes = new TextEncoder().encode(configJson);
  const teePublicKey = hexToBytes(teeKeys.currentPublicKey);
  const encrypted = await wrapKey(configBytes, teePublicKey);
  const encryptedHex = bytesToHex(encrypted);

  try {
    // Call TEE-routed connection test via generated api-client
    const response = await teeControllerConnectionTest({
      encryptedConfig: encryptedHex,
      epoch: teeKeys.currentEpoch,
    });

    return {
      success: response.success,
      protocol: response.protocol as ConnectionTestResult['protocol'],
      version: response.version,
      latencyMs: response.latencyMs,
      error: response.error,
    };
  } finally {
    // Zero plaintext credential buffers (defense-in-depth)
    configBytes.fill(0);
    encrypted.fill(0);
  }
}
