/**
 * The single-use nonce an EIP-4361 message must carry. The engine owns the SIWE
 * exchange itself (`facade.siweLogin`) but exposes no challenge command, so the
 * page fetches the nonce from the API's public challenge endpoint — see #910 to
 * move this below the facade.
 */

/** EIP-4361 requires at least 8 alphanumeric characters. */
const NONCE = /^[A-Za-z0-9]{8,}$/;

export async function requestSiweNonce(apiBaseUrl: string): Promise<string> {
  const response = await fetch(`${apiBaseUrl}/auth/siwe/challenge`, { method: 'POST' });
  if (!response.ok) throw new Error(`siwe challenge refused with ${response.status}`);

  const { nonce } = (await response.json()) as { nonce?: unknown };
  // Fail closed: an unusable nonce must not reach the wallet as a signing prompt.
  if (typeof nonce !== 'string' || !NONCE.test(nonce)) {
    throw new Error('siwe challenge returned an unusable nonce');
  }
  return nonce;
}
