/**
 * Byte helpers shared by the browser seams.
 *
 * The seams key durable stores (IndexedDB records, OPFS file names) by opaque
 * engine-chosen byte strings. A stable lowercase-hex encoding gives every
 * `Uint8Array` a deterministic, collision-free, filesystem-safe string key —
 * no seam ever interprets the bytes it stores, only addresses them.
 */

const HEX = '0123456789abcdef';

/** Lowercase-hex encoding of a byte string; the empty slice maps to `''`. */
export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += HEX[byte >> 4] + HEX[byte & 0x0f];
  }
  return out;
}

/**
 * Inverse of {@link toHex}; `''` maps to an empty byte string.
 *
 * Decodes character-code by character-code — no regex and no `slice`. A
 * successful `RegExp.test` parks its whole input in the realm-global Annex B
 * statics (`RegExp.input`, `RegExp.lastMatch`), and hosts decode secret-bearing
 * hex here (`apps/web` login handoff), which would publish the secret to every
 * script sharing the realm.
 */
export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new TypeError('fromHex: hex string must have an even length');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const high = nibble(hex.charCodeAt(i * 2));
    const low = nibble(hex.charCodeAt(i * 2 + 1));
    if (high < 0 || low < 0) {
      throw new TypeError('fromHex: hex string contains a non-hex character');
    }
    out[i] = (high << 4) | low;
  }
  return out;
}

function nibble(code: number): number {
  if (code >= 0x30 && code <= 0x39) return code - 0x30; // 0-9
  if (code >= 0x61 && code <= 0x66) return code - 0x57; // a-f
  if (code >= 0x41 && code <= 0x46) return code - 0x37; // A-F
  return -1;
}
