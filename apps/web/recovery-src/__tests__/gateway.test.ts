/**
 * Recovery-tool content-address integrity coverage (SC1 / T-78-04).
 *
 * Deterministic, network-free unit test for `verifyRawBlockBytes` — the raw
 * single-block leg of the CID multihash verification `fetchFromIpfs` performs on
 * every fetched block. A hostile/misconfigured gateway that returns altered
 * CTR ciphertext (no auth tag) must be caught here before the bytes are trusted.
 */
import { describe, it, expect } from 'vitest';
import { CID } from 'multiformats/cid';
import { sha256 } from 'multiformats/hashes/sha2';
import * as raw from 'multiformats/codecs/raw';

import { verifyRawBlockBytes } from '../gateway';

/** Build the genuine raw-codec CID (sha2-256) for a block of bytes. */
async function rawCid(bytes: Uint8Array): Promise<string> {
  const digest = await sha256.digest(raw.encode(bytes));
  return CID.create(1, raw.code, digest).toString();
}

describe('verifyRawBlockBytes (CID multihash verification)', () => {
  it('accepts bytes whose sha2-256 digest matches the raw CID', async () => {
    const bytes = new TextEncoder().encode('CipherBox recovered ciphertext block');
    const cid = await rawCid(bytes);

    await expect(verifyRawBlockBytes(cid, bytes)).resolves.toBeUndefined();
  });

  it('rejects tampered bytes (single flipped bit) with a hash-mismatch error', async () => {
    const bytes = new TextEncoder().encode('CipherBox recovered ciphertext block');
    const cid = await rawCid(bytes);

    const tampered = new Uint8Array(bytes);
    tampered[0] ^= 0x01;

    await expect(verifyRawBlockBytes(cid, tampered)).rejects.toThrow(/hash mismatch/i);
  });

  it('rejects bytes whose length was altered by the gateway', async () => {
    const bytes = new TextEncoder().encode('CipherBox recovered ciphertext block');
    const cid = await rawCid(bytes);

    const truncated = bytes.slice(0, bytes.length - 1);

    await expect(verifyRawBlockBytes(cid, truncated)).rejects.toThrow(/hash mismatch/i);
  });

  it('refuses to treat a dag-pb (multi-block) CID as a raw single block', async () => {
    // A CIDv0 (Qm...) is dag-pb — its multihash is over the DAG node, not the
    // assembled bytes, so the raw-block check must not be applied to it.
    const dagPbCidV0 = 'QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG';

    await expect(verifyRawBlockBytes(dagPbCidV0, new Uint8Array([1, 2, 3]))).rejects.toThrow(
      /not a raw single block/i
    );
  });
});
