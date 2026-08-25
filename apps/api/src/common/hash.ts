import { createHash } from 'node:crypto';

/**
 * SHA-256 hex of a credential. Every bearer this API mints is stored only as
 * this digest, so the scheme has to be one function — two copies would let a
 * change land on one token table and not the other.
 */
export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
