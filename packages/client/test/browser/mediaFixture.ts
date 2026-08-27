/**
 * The deterministic plaintext the media browser suite streams. Every realm —
 * page, engine worker, and the Node-side spec — derives the same bytes from
 * `offset` alone, so a byte-exact assertion needs no shared buffer.
 */

/** Bytes produced tab-side, by the harness's own in-page reader. */
export const TAB_SEED = 7;

/** A second tab's bytes, so one tab's stream can never pass as another's. */
export const SECOND_TAB_SEED = 83;

/** Bytes produced only inside the leader's engine worker. */
export const LEADER_SEED = 199;

/**
 * The length the leader's engine worker pins. The fixture answers any offset, so
 * a pinned version needs a stated length — and the head is framed from it, so
 * the spec must mint its ticket for exactly this many bytes.
 */
export const LEADER_CONTENT_BYTES = 96 * 1024;

export function fixtureBuffer(offset: number, length: number, seed: number): ArrayBuffer {
  const buffer = new ArrayBuffer(length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < length; i += 1) bytes[i] = ((offset + i) * 31 + seed) & 0xff;
  return buffer;
}

export function fixtureSlice(offset: number, length: number, seed: number): Uint8Array {
  return new Uint8Array(fixtureBuffer(offset, length, seed));
}
