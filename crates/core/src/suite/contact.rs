//! Encryption subkey binding and the contact code codec (blueprint/core.md
//! "Crypto suite").
//!
//! Every user's identity key only signs and their X25519 encryption subkey only
//! seals. The **subkey binding** is an ECDSA signature over the det-CBOR
//! `{encSubkey, identityPk}` preimage; the **contact code** is the det-CBOR
//! `{bindingSig, encSubkey, identityPk}` triple (~130 bytes, QR/URL-encodable),
//! which [`import_contact_code`] verifies mandatorily and fail-closed.

use crate::codec::{Map, Value, decode, encode_fixed_depth};
use crate::error::{CodecError, Malformed, TrustViolation};

use super::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};
use super::x25519::X25519Public;

/// det-CBOR field name for the secp256k1 identity public key (33-byte SEC1).
const FIELD_IDENTITY_PK: &str = "identityPk";
/// det-CBOR field name for the X25519 encryption subkey (32-byte public key).
const FIELD_ENC_SUBKEY: &str = "encSubkey";
/// det-CBOR field name for the ECDSA binding signature (64-byte compact).
const FIELD_BINDING_SIG: &str = "bindingSig";

/// The det-CBOR preimage the identity signs to bind an encryption subkey:
/// `{encSubkey, identityPk}` in canonical key order. Both codepaths — signing
/// and verifying — build the bytes here, so they can never disagree.
pub fn subkey_binding_preimage(identity_pk: &EcdsaVerifier, enc_subkey: &X25519Public) -> Vec<u8> {
    let mut m = Map::new();
    m.insert(
        FIELD_ENC_SUBKEY,
        Value::Bytes(enc_subkey.to_bytes().to_vec()),
    );
    m.insert(
        FIELD_IDENTITY_PK,
        Value::Bytes(identity_pk.to_sec1().to_vec()),
    );
    encode_fixed_depth(&Value::Map(m))
}

/// Sign the subkey binding: the identity attests that `enc_subkey` is its
/// encryption subkey.
pub fn sign_subkey_binding(identity: &EcdsaSigner, enc_subkey: &X25519Public) -> EcdsaSignature {
    let preimage = subkey_binding_preimage(&identity.verifying_key(), enc_subkey);
    identity.sign_detcbor(&preimage)
}

/// Verify a subkey binding signature. `true` iff `signature` is the identity's
/// ECDSA signature over `{encSubkey, identityPk}`.
pub fn verify_subkey_binding(
    identity_pk: &EcdsaVerifier,
    enc_subkey: &X25519Public,
    signature: &EcdsaSignature,
) -> bool {
    let preimage = subkey_binding_preimage(identity_pk, enc_subkey);
    identity_pk.verify_detcbor(&preimage, signature)
}

/// A verified contact code: an identity key, its bound encryption subkey, and
/// the binding signature. Fields are private so the only ways to obtain one are
/// [`ContactCode::create`] (which signs) and [`import_contact_code`] (which
/// verifies) — holding a `ContactCode` is therefore proof the binding verified,
/// an invariant a public struct literal would let a caller forge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactCode {
    identity_pk: EcdsaVerifier,
    enc_subkey: X25519Public,
    binding_sig: EcdsaSignature,
}

impl ContactCode {
    /// Assemble a contact code from parts and sign the binding with the
    /// identity key. The produced code always imports.
    pub fn create(identity: &EcdsaSigner, enc_subkey: X25519Public) -> Self {
        let binding_sig = sign_subkey_binding(identity, &enc_subkey);
        Self {
            identity_pk: identity.verifying_key(),
            enc_subkey,
            binding_sig,
        }
    }

    /// The verified identity (signing) public key.
    pub fn identity_pk(&self) -> EcdsaVerifier {
        self.identity_pk
    }

    /// The bound X25519 encryption subkey.
    pub fn enc_subkey(&self) -> X25519Public {
        self.enc_subkey
    }

    /// The binding signature.
    pub fn binding_sig(&self) -> &EcdsaSignature {
        &self.binding_sig
    }

    /// Encode to det-CBOR `{bindingSig, encSubkey, identityPk}`.
    pub fn encode(&self) -> Vec<u8> {
        let mut m = Map::new();
        m.insert(
            FIELD_BINDING_SIG,
            Value::Bytes(self.binding_sig.to_compact().to_vec()),
        );
        m.insert(
            FIELD_ENC_SUBKEY,
            Value::Bytes(self.enc_subkey.to_bytes().to_vec()),
        );
        m.insert(
            FIELD_IDENTITY_PK,
            Value::Bytes(self.identity_pk.to_sec1().to_vec()),
        );
        encode_fixed_depth(&Value::Map(m))
    }
}

/// Decode and **verify** a contact code. The binding verify is mandatory and
/// fail-closed: structural defects reject as [`Malformed`], and a well-formed
/// code whose binding does not verify rejects as
/// [`TrustViolation::SubkeyBindingInvalid`]. Unknown fields are tolerated per
/// the profile; the three known fields are read positionally by key.
pub fn import_contact_code(bytes: &[u8]) -> Result<ContactCode, CodecError> {
    let value = decode(bytes)?;
    let map = value.as_map()?;

    let identity_bytes = field_bytes(map, FIELD_IDENTITY_PK)?;
    let identity_pk =
        EcdsaVerifier::from_sec1(identity_bytes).ok_or(Malformed::InvalidIdentityKey)?;

    let enc_bytes = field_bytes(map, FIELD_ENC_SUBKEY)?;
    let enc_array: [u8; 32] = enc_bytes
        .try_into()
        .map_err(|_| Malformed::InvalidEncSubkey)?;
    // A wrong length is malformed; a correct-length but low-order point is a
    // chosen-key attack (grant blobs sealed to it would be world-readable), so
    // it fails closed as a trust violation, not a parse error.
    let enc_subkey =
        X25519Public::from_bytes(enc_array).ok_or(TrustViolation::HpkeNonContributory)?;

    let sig_bytes = field_bytes(map, FIELD_BINDING_SIG)?;
    let binding_sig =
        EcdsaSignature::from_compact(sig_bytes).ok_or(Malformed::InvalidBindingSigEncoding)?;

    if !verify_subkey_binding(&identity_pk, &enc_subkey, &binding_sig) {
        return Err(TrustViolation::SubkeyBindingInvalid.into());
    }

    Ok(ContactCode {
        identity_pk,
        enc_subkey,
        binding_sig,
    })
}

/// Read a required byte-string field, distinguishing an absent field
/// (`missing-field`) from a present-but-wrong-typed one (`unexpected-type`).
fn field_bytes<'a>(map: &'a Map, field: &'static str) -> Result<&'a [u8], CodecError> {
    let value = map.get(field).ok_or(Malformed::MissingField { field })?;
    Ok(value.as_bytes()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar")
    }

    fn enc_subkey() -> X25519Public {
        crate::suite::x25519::X25519Secret::from_scalar([0x33; 32]).public()
    }

    #[test]
    fn sign_verify_binding_round_trip() {
        let id = identity();
        let enc = enc_subkey();
        let sig = sign_subkey_binding(&id, &enc);
        assert!(verify_subkey_binding(&id.verifying_key(), &enc, &sig));
    }

    #[test]
    fn binding_does_not_verify_for_a_different_subkey() {
        let id = identity();
        let sig = sign_subkey_binding(&id, &enc_subkey());
        let other = crate::suite::x25519::X25519Secret::from_scalar([0x44; 32]).public();
        assert!(!verify_subkey_binding(&id.verifying_key(), &other, &sig));
    }

    #[test]
    fn create_encode_import_round_trip() {
        let code = ContactCode::create(&identity(), enc_subkey());
        let bytes = code.encode();
        // ~130-byte key payload (33 + 32 + 64), plus the det-CBOR map frame and
        // camelCase field names — a map (not an array) so the profile's
        // unknown-field tolerance applies. Stays comfortably QR/URL-encodable.
        assert!(
            bytes.len() <= 180,
            "contact code stays compact: {}",
            bytes.len()
        );
        assert_eq!(import_contact_code(&bytes).unwrap(), code);
    }

    #[test]
    fn tampered_binding_rejects_as_trust_violation() {
        let code = ContactCode::create(&identity(), enc_subkey());
        // Re-sign the binding with a *different* identity, then present the
        // original identity key: a structurally valid code whose binding does
        // not verify.
        let forger = EcdsaSigner::from_scalar(&[0x55; 32]).expect("valid scalar");
        let forged = ContactCode {
            identity_pk: code.identity_pk,
            enc_subkey: code.enc_subkey,
            binding_sig: sign_subkey_binding(&forger, &code.enc_subkey),
        };
        let err = import_contact_code(&forged.encode()).unwrap_err();
        assert_eq!(err.check(), "subkey-binding-invalid");
        assert_eq!(err.class(), "trust");
    }
}
