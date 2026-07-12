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
 * Outcome of verifying an IPNS record against the key its name encodes.
 *
 * - `valid`   — signature verifies AND the record is within its validity window.
 * - `expired` — signature verifies (authentic, untampered) but the record's EOL
 *               has passed. The record is stale, NOT forged.
 * - `invalid` — signature/structural verification failed (tampered, malformed,
 *               unsupported key/validity type, or an unparseable name).
 */
export type IpnsSignatureVerdict = 'valid' | 'expired' | 'invalid';

/**
 * Verifies the Ed25519 SignatureV2 of a marshalled IPNS record against the
 * public key encoded in the IPNS name, distinguishing a stale-but-authentic
 * record from a genuinely tampered one.
 *
 * The underlying `ipns` validator throws a distinct `RecordExpiredError` when
 * the signature is good but the validity window (EOL) has passed, versus a
 * `SignatureVerificationError` (or other structural errors) for a forged or
 * malformed record. Callers that must favour availability over freshness (e.g.
 * the break-glass recovery tool) can accept the `expired` verdict, while the
 * strict production read chain rejects anything that is not `valid`.
 *
 * @param ipnsName - IPNS name (CIDv1 base36, e.g. "k51qzi5uqu5...")
 * @param marshalledRecord - The marshalled IPNS record protobuf bytes
 * @returns the verification verdict (see {@link IpnsSignatureVerdict})
 */
export async function verifyIpnsRecordSignatureDetailed(
  ipnsName: string,
  marshalledRecord: Uint8Array
): Promise<IpnsSignatureVerdict> {
  let publicKey: NonNullable<ReturnType<typeof peerIdFromCID>['publicKey']>;
  try {
    // The name is a CIDv1 (libp2p-key codec) whose identity multihash embeds the
    // protobuf-encoded Ed25519 public key. Recover it deterministically.
    const cid = CID.parse(ipnsName, base36);
    const peerId = peerIdFromCID(cid);
    if (peerId.publicKey == null) {
      // Non-inline key (e.g. RSA, where the name is a hash not the key itself).
      // CipherBox only uses Ed25519 identity keys, so treat this as invalid.
      return 'invalid';
    }
    publicKey = peerId.publicKey;
  } catch {
    // Unparseable name / non-CID input — cannot be authentic.
    return 'invalid';
  }

  try {
    // Throws on any signature / structural mismatch; returns void when valid.
    await validate(publicKey, marshalledRecord);
    return 'valid';
  } catch (err) {
    // A valid signature over a past-EOL record still proves authenticity — the
    // record is stale, not forged. `RecordExpiredError` is thrown ONLY after the
    // signature check passes, so this branch is reached exclusively for authentic
    // records. Anything else is a real signature/structural failure.
    if (err instanceof Error && err.name === 'RecordExpiredError') {
      return 'expired';
    }
    return 'invalid';
  }
}

/**
 * Verifies the Ed25519 SignatureV2 of a marshalled IPNS record against the
 * public key encoded in the IPNS name.
 *
 * Possession of the signing private key is proven by a valid signature. This
 * does NOT check ownership or share membership — it answers "is this a valid
 * record for this name?". (The underlying `ipns` validator additionally rejects
 * records whose validity window (EOL) has expired and V1-only records.)
 *
 * Strict semantics: only a fully-valid record returns `true`. A stale (expired)
 * record returns `false`, same as a tampered one — callers needing to tell those
 * apart use {@link verifyIpnsRecordSignatureDetailed}.
 *
 * @param ipnsName - IPNS name (CIDv1 base36, e.g. "k51qzi5uqu5...")
 * @param marshalledRecord - The marshalled IPNS record protobuf bytes
 * @returns true iff the record's signature verifies against the name's key AND
 *   the record is unexpired
 */
export async function verifyIpnsRecordSignature(
  ipnsName: string,
  marshalledRecord: Uint8Array
): Promise<boolean> {
  return (await verifyIpnsRecordSignatureDetailed(ipnsName, marshalledRecord)) === 'valid';
}
