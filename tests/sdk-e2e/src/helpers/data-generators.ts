/**
 * Test data generators for SDK E2E tests.
 * All data is in-memory Uint8Array — no filesystem temp files needed.
 */

/**
 * Generate a Uint8Array of the given size filled with a repeating pattern.
 * The pattern is deterministic for a given seed, enabling content verification.
 */
export function generateBytes(sizeBytes: number, seed = 42): Uint8Array {
  const data = new Uint8Array(sizeBytes);
  for (let i = 0; i < sizeBytes; i++) {
    data[i] = (seed + i * 7 + (i >> 8) * 13) & 0xff;
  }
  return data;
}

/** Generate a text content Uint8Array */
export function generateTextContent(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** Decode Uint8Array back to text */
export function decodeText(data: Uint8Array): string {
  return new TextDecoder().decode(data);
}

/** Common test file sizes */
export const FILE_SIZES = {
  tiny: 100, // 100 bytes
  small: 1_024, // 1 KB
  medium: 50 * 1_024, // 50 KB
  large: 500 * 1_024, // 500 KB
} as const;
