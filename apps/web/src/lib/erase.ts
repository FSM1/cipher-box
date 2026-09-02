/**
 * Erase key bytes this realm still holds.
 *
 * A buffer handed to the engine worker is **transferred, not cloned**, so the
 * view left behind is detached: it holds no bytes here, and `fill` throws on
 * one. Skipping a detached view therefore loses nothing — the realm that took
 * the bytes owns and scrubs the only copy — while an untransferred buffer, such
 * as the rendezvous scalar a requester keeps to open its own factor, is still
 * this realm's to clear.
 */
export function erase(bytes: Uint8Array | null | undefined): void {
  if (bytes != null && bytes.byteLength > 0) bytes.fill(0);
}
