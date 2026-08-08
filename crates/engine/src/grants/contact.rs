//! Contact import — the fail-closed binding-verify at the trust boundary
//! (blueprint/engine.md "Grants and ledger — Contact import", #34 D6).
//!
//! Identity keys arrive only out-of-band; there is no directory. The engine
//! verifies a contact code's binding signature against the carried identity key
//! at import — **mandatory and fail-closed**: a code whose binding does not
//! verify is a hard trust rejection, never a warning and never treated as stale.
//! All of that lives in core's [`import_contact_code`]; this module's job is to
//! hand the rest of the engine a [`Contact`] — a verified owner/sender anchor —
//! that can only ever be produced by a passing verify, so no engine caller can
//! trust an unverified identity by construction.

use cipherbox_core::error::CodecError;
use cipherbox_core::suite::contact::{ContactCode, import_contact_code};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Public;

/// A verified contact: an identity (signing) key and the encryption subkey it
/// bound. There is deliberately no field constructor — a `Contact` is only ever
/// built from a [`ContactCode`], which [`import_contact_code`] returns only on a
/// passing binding verify, so a `Contact` in hand is proof the binding verified.
/// This is the engine-side anchor the mailbox sender-check and the adoption
/// gate's commitment-verify authenticate against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Contact {
    identity_pk: EcdsaVerifier,
    enc_subkey: X25519Public,
}

impl From<&ContactCode> for Contact {
    fn from(code: &ContactCode) -> Self {
        Self {
            identity_pk: code.identity_pk(),
            enc_subkey: code.enc_subkey(),
        }
    }
}

impl Contact {
    /// The verified identity (signing) public key — the commitment/sender-sig
    /// anchor.
    pub fn identity_pk(&self) -> EcdsaVerifier {
        self.identity_pk
    }

    /// The bound X25519 encryption subkey — the blinded-tag ECDH peer and the
    /// grant/mailbox HPKE recipient key.
    pub fn enc_subkey(&self) -> X25519Public {
        self.enc_subkey
    }
}

/// The largest contact code the engine accepts. Every entry point applies it to
/// the offered bytes before [`import_contact`] sees them — the `ImportContact`
/// command and the stored-book codec in
/// [`contact_store`](super::contact_store) — so a new caller must apply it too.
///
/// The bundle is three fixed-width keys — a real one is under 200 bytes — and
/// the bytes arrive as an unbounded host paste or camera scan. Decoding is
/// linear in length, but a decoded `Value` costs far more than the byte it came
/// from, so the cap is what stops a paste from exhausting the engine worker
/// (the resolve path bounds its own reads the same way).
pub const MAX_CONTACT_CODE_BYTES: usize = 1024;

/// Import a contact code, verifying the subkey binding mandatorily and
/// fail-closed. A structural defect surfaces as [`CodecError`] of class
/// `malformed`; a well-formed code whose binding does not verify surfaces as
/// class `trust` (`subkey-binding-invalid`) — the caller distinguishes them via
/// [`CodecError::class`], but neither ever yields a `Contact`.
pub fn import_contact(bytes: &[u8]) -> Result<Contact, CodecError> {
    Ok(Contact::from(&import_contact_code(bytes)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::suite::contact::{ContactCode, sign_subkey_binding};
    use cipherbox_core::suite::ecdsa::EcdsaSigner;
    use cipherbox_core::suite::x25519::X25519Secret;

    fn identity() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar")
    }

    fn enc() -> X25519Public {
        X25519Secret::from_scalar([0x33; 32]).public()
    }

    #[test]
    fn valid_code_imports_to_the_anchored_keys() {
        let id = identity();
        let code = ContactCode::create(&id, enc());
        let contact = import_contact(&code.encode()).expect("valid binding imports");
        assert_eq!(contact.identity_pk(), id.verifying_key());
        assert_eq!(contact.enc_subkey(), enc());
    }

    #[test]
    fn bad_binding_is_a_hard_trust_reject_never_a_contact() {
        // A structurally valid code whose binding was re-signed by a different
        // identity while the real identity key is presented: fail-closed, class
        // `trust`, no Contact produced.
        use cipherbox_core::codec::{Value, decode, encode};
        let good = ContactCode::create(&identity(), enc()).encode();
        let forger = EcdsaSigner::from_scalar(&[0x55; 32]).expect("valid scalar");
        let mut map = decode(&good).unwrap().as_map().unwrap().clone();
        let bad_sig = sign_subkey_binding(&forger, &enc());
        map.insert("bindingSig", Value::Bytes(bad_sig.to_compact().to_vec()));
        let tampered = encode(&Value::Map(map)).unwrap();

        let err = import_contact(&tampered).unwrap_err();
        assert_eq!(err.check(), "subkey-binding-invalid");
        assert_eq!(err.class(), "trust");
    }
}
