/**
 * Error utilities for CipherBox API error handling.
 *
 * The Orval-generated custom instance (custom-instance.ts) throws plain Error
 * objects with a `.status` property attached:
 *
 *   const err = new Error(`HTTP error! status: ${response.status}`);
 *   (err as Error & { status: number }).status = response.status;
 *   throw err;
 *
 * These utilities detect and extract data from such errors.
 */

/**
 * Detect HTTP 409 Conflict errors from the API.
 * Used for IPNS publish conflict detection (sequence number mismatch).
 */
export function isConflictError(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false;
  // Orval custom-instance throws Error objects with .status attached
  const e = error as Record<string, unknown>;
  if (e.status === 409) return true;
  return false;
}

/**
 * Extract the current server sequence number from a 409 conflict error body.
 *
 * NOTE: The current custom-instance does not parse the error body --
 * it only attaches the status code. The server sends currentSequenceNumber
 * in the 409 JSON body, but the client cannot read it from the thrown Error.
 * Future improvement: parse the response body in custom-instance and attach
 * it to the error. For now, callers can re-sync via IPNS resolution.
 */
export function getConflictSequenceNumber(_error: unknown): string | undefined {
  // The custom-instance does not attach the response body to the thrown error.
  // Callers should resolve fresh state via resolveIpnsRecord() instead.
  return undefined;
}
