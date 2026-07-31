/**
 * The single-use nonce an EIP-4361 message must carry. The engine owns the SIWE
 * exchange itself (`facade.siweLogin`) but exposes no challenge command, so the
 * page fetches the nonce from the API's public challenge endpoint — see #910 to
 * move this below the facade.
 */

/** EIP-4361 requires 8+ alphanumerics; the API issues 32 hex characters. */
const NONCE = /^[A-Za-z0-9]{8,128}$/;

const TIMEOUT_MS = 10_000;

export async function requestSiweNonce(apiBaseUrl: string): Promise<string> {
  const response = await fetch(new URL('/auth/siwe/challenge', apiBaseUrl), {
    method: 'POST',
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (!response.ok) throw new Error(`siwe challenge refused with ${response.status}`);

  const { nonce } = (await response.json()) as { nonce?: unknown };
  // Fail closed: an unusable nonce must not reach the wallet as a signing
  // prompt, and its character class is what keeps a hostile response from
  // injecting extra EIP-4361 fields into the signed text.
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) {
    throw new Error('siwe challenge returned an unusable nonce');
  }
  return nonce;
}
