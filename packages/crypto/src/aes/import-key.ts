/**
 * @cipherbox/crypto - AES Key Import Helper
 *
 * Internal helper shared by all AES-GCM and AES-CTR functions to import a raw
 * symmetric key into a Web Crypto CryptoKey. Owns and zeroes its local copy of
 * the key bytes after crypto.subtle.importKey consumes them.
 *
 * D-09: the caller is the terminal owner of `key` — this helper MUST NOT
 * mutate or zero the caller-supplied argument, only its own local copy.
 */

/**
 * Import a raw AES key for use with crypto.subtle.encrypt/decrypt.
 *
 * Allocates a local owned copy of `key` (required because crypto.subtle.importKey
 * needs a plain ArrayBuffer, not a possibly-shared or caller-aliased buffer),
 * imports it, then zeroes the local copy in a finally block. The caller's `key`
 * argument is never read after copying and is never mutated.
 *
 * @param key - 32-byte AES key (borrowed from caller; not mutated)
 * @param algorithm - Web Crypto algorithm identifier, e.g. { name: 'AES-GCM' }
 * @param usages - Key usages, e.g. ['encrypt'] or ['decrypt']
 * @returns Imported CryptoKey
 */
export async function importAesKey(
  key: Uint8Array,
  algorithm: AlgorithmIdentifier,
  usages: KeyUsage[]
): Promise<CryptoKey> {
  // Copy to ensure proper ArrayBuffer (not SharedArrayBuffer) and to avoid
  // aliasing the caller's buffer — this local copy is the only thing zeroed below.
  const keyView = new Uint8Array(key);
  try {
    return await crypto.subtle.importKey(
      'raw',
      keyView.buffer as ArrayBuffer,
      algorithm,
      false,
      usages
    );
  } finally {
    // Best-effort zeroization of our owned copy only — never the caller's `key`.
    keyView.fill(0);
  }
}
