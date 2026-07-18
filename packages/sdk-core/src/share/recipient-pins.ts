/**
 * Recipient-pubkey pin helpers (Phase 80 Plan 04, D-03a/c/e).
 *
 * The owner-sealed `NodeWriteBody.recipientPins` list (base64 raw-pubkey bytes
 * on the wire) is the server-opaque, cross-device trust anchor bound at share /
 * re-mint time. These pure helpers are the single source of truth for the three
 * D-03d enforcement consumers (80-06 Rust, 80-07 TS, 80-08 web) to verify a
 * recipient against, plus the issuance-time append used by the client wrappers.
 *
 * Encoding contract:
 *   - A stored pin is ALWAYS a base64 string of the raw pubkey bytes (produced
 *     by `bytesToBase64`), matching the `encodeWriteBody` / `decodeWriteBody`
 *     wire format in `@cipherbox/core`.
 *   - A `recipient` input may be raw bytes, a hex string (`0x`-prefixed or not),
 *     or a base64 string — `assertRecipientPinned` / `appendRecipientPin`
 *     normalize both sides to raw bytes before comparing so there is never a
 *     hex/base64 mismatch (PATTERNS "0x-strip / hex-decode convention").
 *
 * These helpers NEVER touch key material or IPNS — they are pure functions over
 * the decoded write-body's pin list.
 */

import { base64ToBytes, bytesToBase64, hexToBytes } from '@cipherbox/crypto';
import type { NodeWriteBody } from '@cipherbox/core';

/** A recipient pubkey accepted as raw bytes, hex (`0x`-optional), or base64. */
export type RecipientPubkey = Uint8Array | string;

/** Matches a (possibly `0x`-prefixed) even-length hex string. */
const HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Normalize a recipient pubkey to raw bytes.
 *
 * - `Uint8Array` → a copy of the bytes (never aliases the caller's buffer).
 * - hex string (`0x`-prefixed or bare, even length, hex alphabet) → decoded bytes.
 * - anything else → treated as base64.
 *
 * The hex heuristic is intentionally strict (even length + hex alphabet) so a
 * base64 pubkey (which for a 33/65-byte key is 44/88 chars and contains
 * non-hex base64 characters in practice) is never mis-detected as hex.
 */
function toRawPubkeyBytes(input: RecipientPubkey): Uint8Array {
  if (input instanceof Uint8Array) return Uint8Array.from(input);
  const trimmed = input.trim();
  const bare = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (bare.length > 0 && bare.length % 2 === 0 && HEX_RE.test(bare)) {
    return hexToBytes(bare);
  }
  return base64ToBytes(trimmed);
}

/** Decode a stored pin (always base64) to raw bytes. */
function pinToBytes(pin: string): Uint8Array {
  return base64ToBytes(pin);
}

/** Constant-length-independent byte equality (public data — timing not sensitive). */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Return the recipient-pin list (base64 strings) from a decoded write-body, or
 * `[]` when the write-body is absent or carries no pins.
 */
export function extractRecipientPins(writeBody: NodeWriteBody | null | undefined): string[] {
  return writeBody?.recipientPins ? [...writeBody.recipientPins] : [];
}

/**
 * Return a deduped pin list (base64) that includes `recipient`.
 *
 * Dedup is by raw pubkey bytes, so an existing pin equal to `recipient` under a
 * different encoding is never duplicated. Existing pins are re-encoded to
 * canonical base64 (idempotent for already-canonical input). Does NOT mutate the
 * input list.
 */
export function appendRecipientPin(
  pins: string[] | null | undefined,
  recipient: RecipientPubkey
): string[] {
  const recipientBytes = toRawPubkeyBytes(recipient);
  const seen: Uint8Array[] = [];
  const out: string[] = [];
  const add = (bytes: Uint8Array): void => {
    if (!seen.some((s) => bytesEqual(s, bytes))) {
      seen.push(bytes);
      out.push(bytesToBase64(bytes));
    }
  };
  for (const p of pins ?? []) add(pinToBytes(p));
  add(recipientBytes);
  return out;
}

/**
 * Assert `recipient` is pinned in `pins`, throwing otherwise.
 *
 * Fails CLOSED on an empty or absent pin list (D-03e no-legacy: an absent pin is
 * a hard failure, never a TOFU pass) AND on a non-member recipient. Returns
 * `void` on a raw-byte match. Both sides are normalized to raw bytes before the
 * compare.
 */
export function assertRecipientPinned(
  recipient: RecipientPubkey,
  pins: string[] | null | undefined
): void {
  const list = pins ?? [];
  if (list.length === 0) {
    throw new Error(
      'assertRecipientPinned: recipient pin list is empty or absent — refusing (D-03e no-legacy hard fail)'
    );
  }
  const recipientBytes = toRawPubkeyBytes(recipient);
  for (const p of list) {
    if (bytesEqual(pinToBytes(p), recipientBytes)) return;
  }
  throw new Error(
    'assertRecipientPinned: recipient is not pinned in the node write-body — refusing (D-03d)'
  );
}
