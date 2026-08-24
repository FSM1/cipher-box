/**
 * A pasted contact code as the opaque bytes the engine verifies. This decodes a
 * transport encoding and nothing else — the binding verify is the engine's,
 * mandatory and fail-closed (blueprint/engine.md "Contact import"), so a refusal
 * here is only ever "that paste is not a code", never a verdict about one.
 */

import { fromHex } from '@cipherbox/client';

/** What a paste picks up from a wrapped mail, a QR reader, or a text file. */
const SEPARATORS = new Set([' ', '\t', '\n', '\r']);

/** The pasted code's bytes, or `null` when the paste is not a contact code. */
export function parseContactCode(pasted: string): Uint8Array | null {
  // Char-wise rather than a regex: a `RegExp` match parks its whole input in the
  // realm-global Annex B statics, and this field takes whatever was pasted.
  const compact = [...pasted].filter((char) => !SEPARATORS.has(char)).join('');
  if (compact === '') return null;
  try {
    return fromHex(compact);
  } catch {
    return null;
  }
}
