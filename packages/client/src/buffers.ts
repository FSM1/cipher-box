/**
 * Transferable-buffer custody, shared by every seam that moves one across a
 * realm boundary (AGENTS.md 7).
 *
 * Buffers are branded by the `byteLength` getter rather than `instanceof`, which
 * answers false for a buffer minted in another realm — a worker's, a same-origin
 * frame's — leaving a credential that reached a transfer list from there both
 * copied and unscrubbed.
 */

const byteLengthOf = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength')?.get;

/** An `ArrayBuffer`'s length, or `null` for anything that is not one. */
export function bufferLength(value: unknown): number | null {
  try {
    return (byteLengthOf?.call(value) as number | undefined) ?? null;
  } catch {
    return null;
  }
}

/** Whether `value` is an `ArrayBuffer`, whichever realm minted it. */
export function isBuffer(value: unknown): value is ArrayBuffer {
  return bufferLength(value) !== null;
}

/**
 * Scrubs the buffers a send would have moved. A call that rejects before its
 * send leaves this realm their terminal owner — nothing detaches them and no
 * callee can reach them — so the plaintext is cleared here. A transferred
 * buffer reads as empty, so a send that did run leaves this a no-op.
 */
export function wipeTransfer(transfer: Iterable<unknown> | undefined): void {
  for (const item of transfer ?? []) {
    const length = bufferLength(item);
    if (length !== null && length > 0) new Uint8Array(item as ArrayBuffer).fill(0);
  }
}
