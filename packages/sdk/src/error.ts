/**
 * @cipherbox/sdk - Error handling and retry utilities
 *
 * Framework-agnostic error detection and retry logic for shared folder operations.
 */

/**
 * Check if an error is a 403 Forbidden response (write access revoked).
 *
 * @param error - The caught error object
 * @returns true if the error represents a 403 status
 */
export function isForbiddenError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const e = error as Record<string, unknown>;
  if (e.status === 403) return true;
  if (typeof e.response === 'object' && e.response !== null) {
    return (e.response as Record<string, unknown>).status === 403;
  }
  return false;
}

/**
 * Check if an error is a 409 Conflict response (concurrent modification).
 *
 * @param error - The caught error object
 * @returns true if the error represents a 409 status
 */
export function isConflictError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  const e = error as Record<string, unknown>;
  if (e.status === 409) return true;
  if (typeof e.response === 'object' && e.response !== null) {
    return (e.response as Record<string, unknown>).status === 409;
  }
  return false;
}

/**
 * Extract an HTTP status code from an unknown caught error, if present.
 *
 * Handles both a flat `{ status }` shape and the axios `{ response: { status } }`
 * shape used across the api-client.
 *
 * @param error - The caught error object
 * @returns The numeric status code, or undefined if none can be determined
 */
export function getErrorStatus(error: unknown): number | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const e = error as Record<string, unknown>;
  if (typeof e.status === 'number') return e.status;
  if (typeof e.response === 'object' && e.response !== null) {
    const status = (e.response as Record<string, unknown>).status;
    if (typeof status === 'number') return status;
  }
  return undefined;
}

/**
 * Whether an error represents a deterministic client failure (4xx) that will
 * never succeed on retry — e.g. a 400 validation rejection or a 401/403 auth
 * failure. Transient errors (5xx, network errors with no status) remain retryable.
 *
 * @param error - The caught error object
 * @returns true if the error is a non-retryable 4xx response
 */
export function isNonRetryableError(error: unknown): boolean {
  const status = getErrorStatus(error);
  return status !== undefined && status >= 400 && status < 500;
}

/**
 * Wrap an operation with 403 revocation detection.
 * If the operation throws a 403, calls onRevoked() and re-throws a descriptive error.
 *
 * @param operation - The async operation to execute
 * @param onRevoked - Callback invoked when write access is revoked
 * @returns The operation's result
 * @throws Error with message containing 'write access revoked' on 403
 */
export async function withRevocationGuard<T>(
  operation: () => Promise<T>,
  onRevoked: () => void
): Promise<T> {
  try {
    return await operation();
  } catch (err) {
    if (isForbiddenError(err)) {
      onRevoked();
      throw new Error('Write access revoked. Folder is now read-only.', { cause: err });
    }
    throw err;
  }
}

/**
 * Execute an operation with single-retry on 409 conflict.
 *
 * On conflict: calls resync callback, adds jitter delay, optionally runs
 * pre-retry validation, then retries once. If retry also conflicts, throws.
 *
 * @param perform - The operation to attempt
 * @param resync - Callback to re-fetch fresh state after conflict
 * @param preRetry - Optional validation before retry attempt
 * @returns The operation's result
 */
export async function withConflictRetry<T>(
  perform: () => Promise<T>,
  resync: () => Promise<void>,
  preRetry?: () => void
): Promise<T> {
  try {
    return await perform();
  } catch (err) {
    if (!isConflictError(err)) throw err;
    await resync();
    // Add jitter to reduce collision probability on retry
    await new Promise((r) => setTimeout(r, 200 + Math.random() * 300));
    if (preRetry) preRetry();
    try {
      return await perform();
    } catch (retryErr) {
      if (isConflictError(retryErr)) {
        throw new Error('Folder was modified by another device. Please refresh and try again.');
      }
      throw retryErr;
    }
  }
}
