/**
 * The declared content address a hosted upload carries (blueprint/api.md,
 * Content plane — Ingress). The engine computes every content address in
 * `crates/core`; the API only routes on it, so this reads the multicodec out of
 * the frozen CIDv1 framing without decoding or recomputing anything.
 *
 * The two frozen content-plane shapes (blueprint/core.md): CIDv1 + BLAKE3-256,
 * `raw` for sealed content leaves, `dag-cbor` for DAG roots and record heads.
 * Both share the fixed 4-byte framing `01 <codec> 1e 20`, whose base32 spans the
 * first seven characters — so the prefix identifies the codec exactly.
 *
 * This is a routing hint, never a trust decision: the pin store hands the codec
 * to Kubo, Kubo re-derives the address from the bytes, and the equality check
 * against the declared string is what actually binds bytes to CID.
 */

/** Kubo `cid-codec` names for the frozen content-plane multicodecs. */
const CODEC_BY_PREFIX = {
  bafkr4i: 'raw',
  bafyr4i: 'dag-cbor',
} as const;

export type ContentCidCodec = (typeof CODEC_BY_PREFIX)[keyof typeof CODEC_BY_PREFIX];

/** `b` multibase tag plus the unpadded base32 of the 36 CIDv1 bytes. */
const CONTENT_CID_PATTERN = /^b[a-z2-7]{58}$/;

/**
 * The Kubo `cid-codec` for a declared content CID, or `undefined` when the
 * string is not one of the two frozen content-plane shapes — the caller fails
 * closed on `undefined` rather than guessing a codec.
 */
export function contentCidCodec(cid: string): ContentCidCodec | undefined {
  if (!CONTENT_CID_PATTERN.test(cid)) {
    return undefined;
  }
  return CODEC_BY_PREFIX[cid.slice(0, 7) as keyof typeof CODEC_BY_PREFIX];
}
