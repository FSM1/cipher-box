/**
 * Shared, typed auth/ctx/arg-parsing helpers for the E2E helper scripts (D-04).
 *
 * Extracted verbatim (behavior-preserving, D-07) from
 * `packages/sdk-core/scripts/edit-filepointer.mts` so every migrated helper
 * imports a single typed contract instead of re-deriving auth/ctx.
 *
 * Security: never log or print `accessToken` or `privateKeyHex`. The CLI
 * arg parser refuses `--secret` so the test secret only ever flows through
 * the `TEST_SECRET` environment variable.
 */

import { createAxiosInstance } from '@cipherbox/api-client';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { AuthPayload } from './types';

/**
 * Authenticate against the local/staging E2E API via `/auth/test-login`.
 *
 * @throws if the response is not ok (includes status + body text), or if the
 *   payload is missing `accessToken` or `privateKeyHex`.
 */
export async function authenticate(
  apiUrl: string,
  email: string,
  secret: string
): Promise<AuthPayload> {
  const response = await fetch(`${apiUrl}/auth/test-login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, secret }),
  });

  if (!response.ok) {
    const body = await response.text();
    throw new Error(`test-login failed (${response.status}): ${body}`);
  }

  const payload = (await response.json()) as AuthPayload;

  if (!payload.accessToken || !payload.privateKeyHex) {
    throw new Error('test-login response missing accessToken or privateKeyHex');
  }

  return payload;
}

/**
 * Build a typed {@link SdkContext} backed by an instance-scoped axios client.
 */
export function buildSdkContext(apiUrl: string, accessToken: string): SdkContext {
  const axiosInstance = createAxiosInstance({
    baseUrl: apiUrl,
    getAccessToken: async () => accessToken,
  });

  return {
    apiUrl,
    getAccessToken: async () => accessToken,
    axiosInstance,
  };
}

/**
 * Parse `--key value` CLI args into a flat record.
 *
 * @throws on any non-`--` token, on a missing value, or if `--secret` is
 *   passed (the test secret must come from the `TEST_SECRET` env var only).
 */
export function parseCliArgs(argv: string[]): Record<string, string> {
  const values = new Map<string, string>();

  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) {
      throw new Error(`Unexpected argument: ${token}`);
    }

    const key = token.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing value for --${key}`);
    }

    values.set(key, value);
    i += 1;
  }

  if (values.has('secret')) {
    throw new Error('Do not pass --secret on CLI. Set TEST_SECRET in environment.');
  }

  return Object.fromEntries(values);
}
