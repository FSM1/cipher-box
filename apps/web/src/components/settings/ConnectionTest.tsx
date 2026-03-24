import { useCallback, useEffect, useState } from 'react';
import { testConnection, type ConnectionTestResult } from '@cipherbox/sdk-core';

type ConnectionTestProps = {
  endpoint: string;
  authToken: string;
  onTestResult?: (result: ConnectionTestResult | null) => void;
};

/**
 * Connection test UI for BYO-IPFS node endpoint.
 *
 * Probes the endpoint for Kubo RPC or PSA protocol, displays inline results
 * with protocol auto-detection, and surfaces CORS errors with remediation
 * instructions.
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
      const result = await testConnection(endpoint, authToken || undefined);
      setTestResult(result);
      onTestResult?.(result);
    } catch {
      const errorResult: ConnectionTestResult = {
        success: false,
        latencyMs: 0,
        error: 'could not detect ipfs protocol at this endpoint.',
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
              {testResult.corsError ? (
                <>
                  {testResult.protocol === 'kubo' ||
                  testResult.corsInstructions?.includes('ipfs config') ? (
                    <>
                      {'> failed: cors error. configure cors on your kubo node:'}
                      <pre
                        className="connection-test-cors-instructions"
                        aria-label="CORS configuration commands"
                      >
                        {testResult.corsInstructions}
                      </pre>
                    </>
                  ) : (
                    <>
                      {
                        '> failed: cors error. the pinning service does not allow browser requests. check provider cors settings.'
                      }
                      {testResult.corsInstructions && (
                        <pre
                          className="connection-test-cors-instructions"
                          aria-label="CORS configuration commands"
                        >
                          {testResult.corsInstructions}
                        </pre>
                      )}
                    </>
                  )}
                </>
              ) : testResult.error?.includes('authentication') ? (
                <>{`> failed: authentication failed. check your auth token.`}</>
              ) : (
                <>{`> failed: ${testResult.error || 'could not detect ipfs protocol at this endpoint.'}`}</>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
