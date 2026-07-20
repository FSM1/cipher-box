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

/** Inverse of {@link toHex}; `''` maps to an empty byte string. */
export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
