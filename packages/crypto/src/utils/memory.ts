/**
 * @cipherbox/crypto - Memory Utilities
 *
 * Best-effort memory clearing for sensitive data.
 *
 * IMPORTANT: JavaScript does not guarantee memory clearing.
 * The garbage collector controls actual memory deallocation, and copies
 * may exist in JIT-compiled code or V8 internals. These functions provide
 * best-effort clearing by overwriting buffer contents, but should not be
 * relied upon for absolute security in memory-sensitive contexts.
 */

/**
 * Clear sensitive data from a Uint8Array (best-effort).
 *
 * Overwrites all bytes with zeros. This is a defense-in-depth measure,
 * not a guarantee of secure erasure.
 *
 * @param data - Buffer to clear (null-safe)
 */
export function clearBytes(data: Uint8Array | null): void {
  if (data) {
    data.fill(0);
  }
}

/**
 * Clear multiple buffers at once.
 *
 * @param buffers - Buffers to clear (null-safe)
 */
export function clearAll(...buffers: (Uint8Array | null)[]): void {
  for (const buffer of buffers) {
    clearBytes(buffer);
  }
}
