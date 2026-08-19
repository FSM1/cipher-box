/**
 * Canonical RFC 4122 UUID. Row ids are always server-minted uuids, so any other
 * shape can never name a row; matching this before a lookup or delete keeps a
 * malformed id from reaching a `uuid`-typed column, where Postgres raises 22P02
 * and turns a documented no-op into a 500.
 */
export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Base64 over the standard alphabet, padding optional. */
export const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

/**
 * Base64 in full padded quartets. Anything a SIGNATURE covers as text must be
 * pinned this way: an unpadded or short-quartet spelling decodes and re-encodes
 * to a different string, so the bytes served back would stop matching the bytes
 * signed. It is a cheap pre-filter, not the whole rule — `AB==` and `AA==` both
 * match and both decode to one byte, so the round trip is still checked where
 * the bytes are decoded.
 */
export const CANONICAL_BASE64_RE =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$/;
