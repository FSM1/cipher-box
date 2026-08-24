/**
 * A pasted contact code as the opaque bytes the engine verifies. This decodes a
 * transport encoding and nothing else — the binding verify is the engine's,
 * mandatory and fail-closed (blueprint/engine.md "Contact import").
 */

import { fromHex } from '@cipherbox/client';

const SEPARATORS = new Set([' ', '\t', '\n', '\r']);

/**
 * Field bound, not the protocol's — the engine owns the code's real size limit.
 * A mis-paste can be a whole document, and decoding one costs memory linear in
 * its length; this is far above any code the engine would accept.
 */
export const MAX_PASTED_CHARS = 8192;

/**
 * The pasted code's bytes, or `null` when the paste is not a code at all — a
 * decode refusal, never a verdict about a code the engine has seen.
 */
export function parseContactCode(pasted: string): Uint8Array | null {
  if (pasted.length > MAX_PASTED_CHARS) return null;
  // Char-wise rather than a regex, for the reason `fromHex` documents: a match
  // parks its whole input in the realm-global statics, and this field takes a paste.
  let compact = '';
  for (const char of pasted) {
    if (!SEPARATORS.has(char)) compact += char;
  }
  if (compact === '') return null;
  try {
    return fromHex(compact);
  } catch {
    return null;
  }
}
