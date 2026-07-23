//! The mailbox payload: an HPKE-sealed item carrying a sender identity
//! signature **inside** the seal (blueprint/core.md "Pointer payloads —
//! Mailbox payloads", CONTEXT.md "Mailbox", #39 D9).
//!
//! The mailbox is the API's integrity-*untrusted* transport: anyone can HPKE-
//! seal to a recipient's encryption subkey (base mode is anonymous), so the
//! trust comes entirely from the sender signature the recipient verifies after
//! opening, against the contact-code-anchored identity key. Unauthenticated
//! items are dropped; the mailbox carries discovery and courtesy traffic only.
//!
//! Wire shape. The HPKE plaintext is det-CBOR
//! `{payload, senderIdentityPk, senderSig}`: the opaque application `payload`,
//! the sender's 33-byte compressed secp256k1 identity key, and the 64-byte
//! ECDSA signature over `[domain, v, recipientEncPk, senderIdentityPk, payload]`
//! (domain-, version-, recipient-, and key-bound so a signature can never be
//! lifted onto a different sender, recipient, or protocol version — a recipient
//! cannot relay-lift an opened item's `{payload, senderSig}` onto a second
//! recipient). That plaintext is HPKE-sealed with the
//! `mailbox-payload` AAD as the RFC 9180 `info`, and the published block is
//! det-CBOR `{enc, ct}`. The recipient supplies the protocol version `v`
//! out-of-band, so a version downgrade recomputes a different key schedule and
//! fails the AEAD tag ([`TrustViolation::HpkeOpenFailed`]).

use zeroize::Zeroize;

use crate::codec::{Map, Value, decode, encode};
use crate::error::{CodecError, TrustViolation};
use crate::seal::{AadContext, STRUCT_TAG_MAILBOX_PAYLOAD, build_aad};
use crate::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};
use crate::suite::hpke::{self, hpke_open, hpke_seal};
use crate::suite::x25519::{X25519Public, X25519Secret};

use super::{bytes_fixed, req};

/// The sender-signature domain separator: the signature covers
/// `[MAILBOX_SIG_DOMAIN, v, recipientEncPk, senderIdentityPk, payload]`.
const MAILBOX_SIG_DOMAIN: &str = "cipherbox/v2/mailbox-sig";

/// An opened, sender-verified mailbox item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxItem {
    /// The opaque application payload (the caller frames its meaning).
    pub payload: Vec<u8>,
    /// The verified sender identity key (anchor it against the contact code).
    pub sender_identity: EcdsaVerifier,
}

/// The AAD context of a mailbox payload at version `v`. A mailbox item is
/// recipient-addressed, not node/scope/epoch-bound, so those fields are zero;
/// only `v` and the `mailbox-payload` tag are load-bearing.
fn mailbox_ctx(v: u64) -> AadContext {
    AadContext {
        v,
        id: [0; 16],
        scope: [0; 16],
        epoch: 0,
        struct_tag: STRUCT_TAG_MAILBOX_PAYLOAD,
    }
}

/// The sender-signature preimage. Binding `recipient_pk` closes the
/// cross-recipient relay lift: an opened item cannot be re-sealed to a second
/// recipient and still verify.
fn sig_preimage(v: u64, recipient_pk: &[u8], sender_pk: &[u8], payload: &[u8]) -> Vec<u8> {
    encode(&Value::Array(vec![
        Value::Text(MAILBOX_SIG_DOMAIN.to_string()),
        Value::Unsigned(v),
        Value::Bytes(recipient_pk.to_vec()),
        Value::Bytes(sender_pk.to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// Seal a mailbox payload to `recipient_enc_pub`. `ephemeral_scalar` is the
/// injected, fresh-per-call HPKE ephemeral secret (KATs pin it; production
/// callers source it from their entropy seam — reuse under one recipient is a
/// catastrophic break). The sender signs inside the seal. Returns the published
/// block bytes.
pub fn seal_mailbox_payload(
    recipient_enc_pub: &X25519Public,
    ephemeral_scalar: &[u8; 32],
    v: u64,
    sender_signer: &EcdsaSigner,
    payload: &[u8],
) -> Vec<u8> {
    let sender_pk = sender_signer.verifying_key().to_sec1();
    let mut preimage = sig_preimage(v, &recipient_enc_pub.to_bytes(), &sender_pk, payload);
    let sender_sig = sender_signer.sign_detcbor(&preimage);
    preimage.zeroize();

    let mut inner_map = Map::new();
    inner_map.insert("payload", Value::Bytes(payload.to_vec()));
    inner_map.insert("senderIdentityPk", Value::Bytes(sender_pk.to_vec()));
    inner_map.insert("senderSig", Value::Bytes(sender_sig.to_compact().to_vec()));
    let mut inner = encode(&Value::Map(inner_map));

    let info = build_aad(&mailbox_ctx(v));
    let sealed = hpke_seal(recipient_enc_pub, ephemeral_scalar, &info, &[], &inner);
    inner.zeroize();

    let mut block = Map::new();
    block.insert("ct", Value::Bytes(sealed.ciphertext));
    block.insert("enc", Value::Bytes(sealed.enc.to_vec()));
    encode(&Value::Map(block))
}

/// Open + verify a mailbox payload. HPKE-open under `recipient_secret` and the
/// reconstructed `mailbox-payload` info (a tamper, wrong recipient, or version
/// downgrade is [`TrustViolation::HpkeOpenFailed`]), then verify the sender's
/// ECDSA signature (a bad key, non-canonical signature, or mismatch is
/// [`TrustViolation::IdentitySignatureInvalid`]). A structurally ill-formed
/// block or plaintext is [`Malformed`](crate::error::Malformed).
pub fn open_mailbox_payload(
    recipient_secret: &X25519Secret,
    v: u64,
    block: &[u8],
) -> Result<MailboxItem, CodecError> {
    let block_value = decode(block)?;
    let block_map = block_value.as_map()?;
    let ct = req(block_map, "ct")?.as_bytes()?;
    let enc = bytes_fixed::<{ hpke::ENC_LEN }>(req(block_map, "enc")?, "enc")?;

    let info = build_aad(&mailbox_ctx(v));
    let mut inner = hpke_open(recipient_secret, &enc, &info, &[], ct).map_err(CodecError::from)?;
    let recipient_pk = recipient_secret.public().to_bytes();
    let result = verify_inner(&inner, v, &recipient_pk);
    inner.zeroize();
    result
}

fn verify_inner(inner: &[u8], v: u64, recipient_pk: &[u8]) -> Result<MailboxItem, CodecError> {
    let value = decode(inner)?;
    let map = value.as_map()?;
    let payload = req(map, "payload")?.as_bytes()?.to_vec();
    let sender_pk = req(map, "senderIdentityPk")?.as_bytes()?;
    let sig_bytes = req(map, "senderSig")?.as_bytes()?;

    let sender_identity =
        EcdsaVerifier::from_sec1(sender_pk).ok_or(TrustViolation::IdentitySignatureInvalid)?;
    let sig =
        EcdsaSignature::from_compact(sig_bytes).ok_or(TrustViolation::IdentitySignatureInvalid)?;
    let mut preimage = sig_preimage(v, recipient_pk, sender_pk, &payload);
    let verified = sender_identity.verify_detcbor(&preimage, &sig);
    preimage.zeroize();
    if !verified {
        return Err(TrustViolation::IdentitySignatureInvalid.into());
    }
    Ok(MailboxItem {
        payload,
        sender_identity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recipient() -> X25519Secret {
        X25519Secret::from_scalar([0x40; 32])
    }

    fn sender() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar")
    }

    #[test]
    fn seal_open_round_trip_and_sender_identity() {
        let eph = [0x51; 32];
        let block =
            seal_mailbox_payload(&recipient().public(), &eph, 2, &sender(), b"discovery ping");
        let item = open_mailbox_payload(&recipient(), 2, &block).unwrap();
        assert_eq!(item.payload, b"discovery ping");
        assert_eq!(item.sender_identity, sender().verifying_key());
    }

    #[test]
    fn tampered_ciphertext_fails_hpke_open() {
        let eph = [0x51; 32];
        let block = seal_mailbox_payload(&recipient().public(), &eph, 2, &sender(), b"x");
        // Flip a byte inside the ct field and re-encode.
        let mut m = decode(&block).unwrap().as_map().unwrap().clone();
        let mut ct = m.get("ct").unwrap().as_bytes().unwrap().to_vec();
        ct[0] ^= 0x01;
        m.insert("ct", Value::Bytes(ct));
        let tampered = encode(&Value::Map(m));
        assert_eq!(
            open_mailbox_payload(&recipient(), 2, &tampered)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn version_downgrade_fails_hpke_open() {
        let eph = [0x51; 32];
        let block = seal_mailbox_payload(&recipient().public(), &eph, 2, &sender(), b"x");
        // Opening under a different v recomputes the info → key schedule → tag.
        assert_eq!(
            open_mailbox_payload(&recipient(), 1, &block)
                .unwrap_err()
                .check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn wrong_recipient_fails_hpke_open() {
        let eph = [0x51; 32];
        let block = seal_mailbox_payload(&recipient().public(), &eph, 2, &sender(), b"x");
        let other = X25519Secret::from_scalar([0x41; 32]);
        assert_eq!(
            open_mailbox_payload(&other, 2, &block).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn forged_sender_signature_fails_identity_check() {
        // Seal a well-formed item whose senderSig is garbage: HPKE opens (anyone
        // can seal), but the sender signature does not verify.
        let eph = [0x51; 32];
        let sender_pk = sender().verifying_key().to_sec1();
        let mut inner = Map::new();
        inner.insert("payload", Value::Bytes(b"forged".to_vec()));
        inner.insert("senderIdentityPk", Value::Bytes(sender_pk.to_vec()));
        // A valid-encoding but wrong signature (sign a different message).
        let wrong = sender().sign_detcbor(b"not the preimage");
        inner.insert("senderSig", Value::Bytes(wrong.to_compact().to_vec()));
        let inner_bytes = encode(&Value::Map(inner));
        let info = build_aad(&mailbox_ctx(2));
        let sealed = hpke_seal(&recipient().public(), &eph, &info, &[], &inner_bytes);
        let mut block = Map::new();
        block.insert("ct", Value::Bytes(sealed.ciphertext));
        block.insert("enc", Value::Bytes(sealed.enc.to_vec()));
        let block_bytes = encode(&Value::Map(block));
        assert_eq!(
            open_mailbox_payload(&recipient(), 2, &block_bytes)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    #[test]
    fn relay_to_other_recipient_fails_identity_check() {
        // R1 opens an item sealed to it, then re-seals the untouched inner
        // plaintext — sender signature included — to a second recipient R2.
        // Recipient binding makes R2's signature check fail (#712).
        let r1 = recipient();
        let r2 = X25519Secret::from_scalar([0x42; 32]);
        let block = seal_mailbox_payload(&r1.public(), &[0x54; 32], 2, &sender(), b"relayed");

        let info = build_aad(&mailbox_ctx(2));
        let m = decode(&block).unwrap().as_map().unwrap().clone();
        let ct = m.get("ct").unwrap().as_bytes().unwrap().to_vec();
        let enc = bytes_fixed::<{ hpke::ENC_LEN }>(m.get("enc").unwrap(), "enc").unwrap();
        let inner = hpke_open(&r1, &enc, &info, &[], &ct).unwrap();

        let sealed = hpke_seal(&r2.public(), &[0x53; 32], &info, &[], &inner);
        let mut relay = Map::new();
        relay.insert("ct", Value::Bytes(sealed.ciphertext));
        relay.insert("enc", Value::Bytes(sealed.enc.to_vec()));
        let relay_block = encode(&Value::Map(relay));

        assert_eq!(
            open_mailbox_payload(&r2, 2, &relay_block)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    #[test]
    fn per_recipient_binding_both_verify() {
        // The binding is per-recipient, not pinned to one key: a sender seals
        // separately to R1 and R2 and both verify, while a cross-open fails
        // HPKE rather than silently verifying (#712).
        let s = sender();
        let r1 = recipient();
        let r2 = X25519Secret::from_scalar([0x42; 32]);
        let b1 = seal_mailbox_payload(&r1.public(), &[0x51; 32], 2, &s, b"to-r1");
        let b2 = seal_mailbox_payload(&r2.public(), &[0x52; 32], 2, &s, b"to-r2");
        assert_eq!(open_mailbox_payload(&r1, 2, &b1).unwrap().payload, b"to-r1");
        assert_eq!(open_mailbox_payload(&r2, 2, &b2).unwrap().payload, b"to-r2");
        assert_eq!(
            open_mailbox_payload(&r2, 2, &b1).unwrap_err().check(),
            "hpke-open-failed"
        );
    }

    #[test]
    fn same_recipient_reseal_still_verifies() {
        // The reject is specifically cross-recipient (#712), not "any re-seal
        // breaks": R1 re-seals its own item to itself under a fresh ephemeral
        // and it still verifies — the recipient tag, not the reseal act, is
        // what the signature binds.
        let r1 = recipient();
        let block = seal_mailbox_payload(&r1.public(), &[0x54; 32], 2, &sender(), b"relayed");

        let info = build_aad(&mailbox_ctx(2));
        let m = decode(&block).unwrap().as_map().unwrap().clone();
        let ct = m.get("ct").unwrap().as_bytes().unwrap().to_vec();
        let enc = bytes_fixed::<{ hpke::ENC_LEN }>(m.get("enc").unwrap(), "enc").unwrap();
        let inner = hpke_open(&r1, &enc, &info, &[], &ct).unwrap();

        let resealed = hpke_seal(&r1.public(), &[0x55; 32], &info, &[], &inner);
        let mut block2 = Map::new();
        block2.insert("ct", Value::Bytes(resealed.ciphertext));
        block2.insert("enc", Value::Bytes(resealed.enc.to_vec()));
        let block2_bytes = encode(&Value::Map(block2));

        let item = open_mailbox_payload(&r1, 2, &block2_bytes).unwrap();
        assert_eq!(item.payload, b"relayed");
        assert_eq!(item.sender_identity, sender().verifying_key());
    }
}
