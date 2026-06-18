/**
 * @cipherbox/crypto - IPNS Record Signature Verification
 *
 * Verifies that a marshalled IPNS record was signed by the private key that the
 * IPNS name encodes. For Ed25519 "identity" keys (CipherBox's only kind), the
 * IPNS name (`k51...`, a CIDv1 with the libp2p-key codec) embeds the public key,
 * so the name alone is sufficient to derive the verifying key — no out-of-band
 * public key is required.
 *
 * This is the authority check for CipherBox's decentralized IPNS model: any
 * caller presenting a validly-signed record for a name may update that name's
 * value, because only the holder of the private key can produce such a record.
 */

import { peerIdFromCID } from '@libp2p/peer-id';
import { CID } from 'multiformats/cid';
import { base36 } from 'multiformats/bases/base36';
import { validate } from 'ipns/validator';

/**
 * Verifies the Ed25519 SignatureV2 of a marshalled IPNS record against the
 * public key encoded in the IPNS name.
 *
 * Possession of the signing private key is proven by a valid signature. This
 * does NOT check ownership or share membership — it answers "is this a valid
 * record for this name?". (The underlying `ipns` validator additionally rejects
 * records whose validity window (EOL) has expired and V1-only records.)
 *
 * @param ipnsName - IPNS name (CIDv1 base36, e.g. "k51qzi5uqu5...")
 * @param marshalledRecord - The marshalled IPNS record protobuf bytes
 * @returns true iff the record's signature verifies against the name's key
 */
export async function verifyIpnsRecordSignature(
  ipnsName: string,
  marshalledRecord: Uint8Array
): Promise<boolean> {
  try {
    // The name is a CIDv1 (libp2p-key codec) whose identity multihash embeds the
    // protobuf-encoded Ed25519 public key. Recover it deterministically.
    const cid = CID.parse(ipnsName, base36);
    const peerId = peerIdFromCID(cid);
    if (peerId.publicKey == null) {
      // Non-inline key (e.g. RSA, where the name is a hash not the key itself).
      // CipherBox only uses Ed25519 identity keys, so treat this as invalid.
      return false;
    }
    // Throws on any signature / structural mismatch; returns void when valid.
    await validate(peerId.publicKey, marshalledRecord);
    return true;
  } catch {
    return false;
  }
}
