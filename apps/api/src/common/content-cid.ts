/**
 * Reads the Kubo `cid-codec` off a declared content address (blueprint/api.md,
 * Content plane — Ingress). The multicodec of the fixed CIDv1 framing
 * `01 <codec> 1e 20` lands wholly inside the first six base32 characters, so the
 * prefix names it exactly — no decoding, and no content address computed in
 * TypeScript. Drift from core's framing fails the contract suite's upload leg,
 * which pins a core-computed leaf and DAG root through this lookup.
 */

/** The frozen content-plane multicodecs (blueprint/core.md), by CID prefix. */
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
