import type { MediaService } from '@cipherbox/client';

/**
 * A `/stream/` ticket for `node`, or `null` where this tab must buffer the read
 * instead. A size past `Number.MAX_SAFE_INTEGER` is not addressable by a Range,
 * so it fails closed rather than serving a truncated file.
 */
export function streamTicket(
  media: MediaService | null,
  node: Uint8Array,
  size: bigint | null,
  mimeType: string
): string | null {
  if (media === null || size === null || !media.streaming) return null;
  const bytes = Number(size);
  return Number.isSafeInteger(bytes)
    ? media.createStreamUrl({ node, size: bytes, mimeType })
    : null;
}
