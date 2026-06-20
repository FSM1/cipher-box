/**
 * Shared types for the typed E2E helper module.
 */

/**
 * Payload returned by the `/auth/test-login` endpoint.
 *
 * `publicKeyHex` is optional: verify-filepointer authenticates without
 * requiring it, so it must stay optional to preserve behavior across all
 * consumers (D-07).
 */
export interface AuthPayload {
  accessToken: string;
  privateKeyHex: string;
  publicKeyHex?: string;
}
