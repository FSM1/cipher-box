//! The pointer payload: the owner-signed, `pointerReadKey`-sealed re-point
//! object (blueprint/core.md "Pointer payloads", CONTEXT.md "Re-point object").
//!
//! Wire shape. The sealed plaintext is det-CBOR `{object, ownerSig}` where
//! `object` is the re-point object map (the owner's ECDSA signature preimage,
//! carried verbatim so verify signs the exact bytes) and `ownerSig` is the
//! 64-byte compact signature. That plaintext is sealed with the symmetric
//! [`seal`](crate::seal) path under `pointerReadKey`, binding the
//! `pointer-payload` AAD `(v, scope, scope, 0, tag)`. The published block is
//! that sealed blob (`nonce || ciphertext||tag`); the reader already knows the
//! scope, so the AAD context is reconstructible without a plaintext envelope.
//!
//! The AAD `epoch` is fixed to `0`: a pointer is the epoch-*advancing* anchor,
//! not an epoch-tagged node body, and the reader cannot know the write epoch
//! before unsealing — the authoritative `writeEpoch`/`minReadEpoch` are the
//! sealed, owner-signed payload. `id` and `scope` both carry the scope id, so a
//! pointer sealed for one scope can never open under another.

use core::fmt;

use zeroize::Zeroize;

use crate::codec::scrub::{ScrubOnDrop, ScrubOwned};
use crate::codec::{Map, RedactedText, Value, decode, encode, encode_fixed_depth};
use crate::error::{CodecError, Malformed, TrustViolation};
use crate::ipns::IpnsName;
use crate::seal::{AadContext, STRUCT_TAG_POINTER_PAYLOAD};
use crate::suite::aead::{KEY_LEN, NONCE_LEN};
use crate::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier, SIGNATURE_LEN};

use super::{bytes_fixed, req};

/// The re-point object published at a scope (or vault) pointer. Owner-signed
/// and owner-maintained; the cold-start floor anchor (`minReadEpoch`).
///
/// The root names render redacted: hiding the pointer-to-current-root binding
/// is what this payload's seal is *for*, and `prev_root` exposes the migration
/// window on top of it.
#[derive(Clone, PartialEq, Eq)]
pub struct RepointObject {
    /// The scope id (the scope root's 16-byte node UUID).
    pub scope_id: [u8; 16],
    /// The scope root's current `ipnsName`.
    pub current_root: IpnsName,
    /// The current write-plane epoch.
    pub write_epoch: u64,
    /// The owner-vouched minimum read epoch — the revocation floor, bumped only
    /// by owner-triggered read rotations (never rolled back).
    pub min_read_epoch: u64,
    /// The previous root name during a migration window, if any.
    pub prev_root: Option<IpnsName>,
}

impl fmt::Debug for RepointObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepointObject")
            .field("scope_id", &self.scope_id)
            .field(
                "current_root",
                &RedactedText::of(self.current_root.as_str()),
            )
            .field("write_epoch", &self.write_epoch)
            .field("min_read_epoch", &self.min_read_epoch)
            .field(
                "prev_root",
                &self
                    .prev_root
                    .as_ref()
                    .map(|n| RedactedText::of(n.as_str())),
            )
            .finish()
    }
}

/// The det-CBOR preimage the owner identity signs to authorise a re-point:
/// `{currentRootName, minReadEpoch, prevRootName?, scopeId, writeEpoch}` in
/// canonical key order. [`seal_pointer_payload`] signs exactly these bytes.
///
/// The returned buffer carries the scope's root names verbatim, so its caller is
/// the terminal owner and must zeroize it — the seal path does.
pub fn repoint_preimage(object: &RepointObject) -> Vec<u8> {
    let mut tree = object.to_value();
    let guard = ScrubOnDrop(&mut tree);
    encode_fixed_depth(guard.0)
}

impl RepointObject {
    fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "currentRootName",
            Value::Text(self.current_root.as_str().to_string()),
        );
        m.insert("minReadEpoch", Value::Unsigned(self.min_read_epoch));
        if let Some(prev) = &self.prev_root {
            m.insert("prevRootName", Value::Text(prev.as_str().to_string()));
        }
        m.insert("scopeId", Value::Bytes(self.scope_id.to_vec()));
        m.insert("writeEpoch", Value::Unsigned(self.write_epoch));
        Value::Map(m)
    }

    fn from_value(v: &Value) -> Result<Self, CodecError> {
        let m = v.as_map()?;
        let scope_id = bytes_fixed::<16>(req(m, "scopeId")?, "scopeId")?;
        let current_root = IpnsName::parse(req(m, "currentRootName")?.as_text()?)?;
        let write_epoch = req(m, "writeEpoch")?.as_unsigned()?;
        let min_read_epoch = req(m, "minReadEpoch")?.as_unsigned()?;
        let prev_root = match m.get("prevRootName") {
            Some(v) => Some(IpnsName::parse(v.as_text()?)?),
            None => None,
        };
        Ok(Self {
            scope_id,
            current_root,
            write_epoch,
            min_read_epoch,
            prev_root,
        })
    }
}

/// The AAD context of a pointer payload for `scope_id` at version `v`.
fn pointer_ctx(v: u64, scope_id: [u8; 16]) -> AadContext {
    AadContext {
        v,
        id: scope_id,
        scope: scope_id,
        epoch: 0,
        struct_tag: STRUCT_TAG_POINTER_PAYLOAD,
    }
}

/// Seal a re-point object: owner-sign it, wrap `{object, ownerSig}`, and seal
/// that under `pointer_read_key` with the `pointer-payload` AAD. `nonce` must be
/// unique per key (injected entropy the KAT pins); the object's `scope_id` sets
/// the AAD scope. Returns the published block bytes.
pub fn seal_pointer_payload(
    pointer_read_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    v: u64,
    owner_signer: &EcdsaSigner,
    object: &RepointObject,
) -> Vec<u8> {
    let object_value = object.to_value();
    let mut object_bytes = repoint_preimage(object);
    let owner_sig = owner_signer.sign_detcbor(&object_bytes);
    object_bytes.zeroize();

    let mut m = Map::new();
    m.insert("object", object_value);
    m.insert("ownerSig", Value::Bytes(owner_sig.to_compact().to_vec()));
    let mut plaintext = {
        let mut tree = Value::Map(m);
        let guard = ScrubOnDrop(&mut tree);
        encode_fixed_depth(guard.0)
    };

    let sealed = crate::seal::seal(
        pointer_read_key,
        nonce,
        &pointer_ctx(v, object.scope_id),
        &plaintext,
    );
    plaintext.zeroize();
    sealed
}

/// Open + verify a pointer payload. Unseal under `pointer_read_key` and the
/// reconstructed `pointer-payload` AAD (a transplant, downgrade, or tamper is
/// [`TrustViolation::SealOpenFailed`]), then verify the owner's ECDSA signature
/// over the exact `object` bytes against `owner_identity` (a mismatch is
/// [`TrustViolation::IdentitySignatureInvalid`]). A structurally ill-formed
/// plaintext is [`Malformed`].
pub fn open_pointer_payload(
    pointer_read_key: &[u8; KEY_LEN],
    v: u64,
    scope_id: &[u8; 16],
    owner_identity: &EcdsaVerifier,
    block: &[u8],
) -> Result<RepointObject, CodecError> {
    let mut plaintext = crate::seal::unseal(pointer_read_key, &pointer_ctx(v, *scope_id), block)?;
    let result = decode_and_verify(&plaintext, owner_identity);
    plaintext.zeroize();
    result
}

/// The transient decoded tree copies the root names, so it is scrubbed on drop;
/// the returned object's own copies are the caller's.
fn decode_and_verify(
    plaintext: &[u8],
    owner_identity: &EcdsaVerifier,
) -> Result<RepointObject, CodecError> {
    let value = ScrubOwned(decode(plaintext)?);
    let map = value.value().as_map()?;

    let object_value = req(map, "object")?;
    let sig_bytes = req(map, "ownerSig")?.as_bytes()?;
    if sig_bytes.len() != SIGNATURE_LEN {
        return Err(Malformed::InvalidFieldLength {
            field: "ownerSig",
            expected: SIGNATURE_LEN,
            found: sig_bytes.len(),
        }
        .into());
    }
    let sig =
        EcdsaSignature::from_compact(sig_bytes).ok_or(TrustViolation::IdentitySignatureInvalid)?;

    // The decoder admits canonical input only, so re-encoding the decoded
    // `object` reproduces the exact bytes the owner signed.
    let mut object_bytes = encode(object_value)?;
    let verified = owner_identity.verify_detcbor(&object_bytes, &sig);
    object_bytes.zeroize();
    if !verified {
        return Err(TrustViolation::IdentitySignatureInvalid.into());
    }
    RepointObject::from_value(object_value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::ed25519::Ed25519Signer;

    fn name(seed: u8) -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([seed; 32]).verifying_key())
    }

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x21; 32]).expect("valid scalar")
    }

    fn object() -> RepointObject {
        RepointObject {
            scope_id: [7; 16],
            current_root: name(1),
            write_epoch: 4,
            min_read_epoch: 2,
            prev_root: Some(name(2)),
        }
    }

    /// Hiding the pointer-to-root binding is what the seal is for; no `{:?}`
    /// may hand it back.
    #[test]
    fn debug_redacts_the_root_names() {
        let obj = object();
        let rendered = format!("{obj:?}");
        assert!(!rendered.contains(obj.current_root.as_str()), "{rendered}");
        assert!(
            !rendered.contains(obj.prev_root.as_ref().unwrap().as_str()),
            "{rendered}"
        );
        assert!(
            rendered.contains("min_read_epoch: 2"),
            "the floor stays legible: {rendered}"
        );
    }

    #[test]
    fn seal_open_round_trip() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let obj = object();
        let block = seal_pointer_payload(&key, &nonce, 2, &owner(), &obj);
        let opened =
            open_pointer_payload(&key, 2, &obj.scope_id, &owner().verifying_key(), &block).unwrap();
        assert_eq!(opened, obj);
    }

    #[test]
    fn first_publish_object_has_no_prev_root() {
        let key = [1u8; KEY_LEN];
        let nonce = [2u8; NONCE_LEN];
        let obj = RepointObject {
            prev_root: None,
            ..object()
        };
        let block = seal_pointer_payload(&key, &nonce, 2, &owner(), &obj);
        let opened =
            open_pointer_payload(&key, 2, &obj.scope_id, &owner().verifying_key(), &block).unwrap();
        assert_eq!(opened.prev_root, None);
    }

    #[test]
    fn tampered_block_fails_the_seal_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let mut block = seal_pointer_payload(&key, &nonce, 2, &owner(), &object());
        let last = block.len() - 1;
        block[last] ^= 0x01;
        assert_eq!(
            open_pointer_payload(&key, 2, &[7; 16], &owner().verifying_key(), &block)
                .unwrap_err()
                .check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn scope_transplant_fails_the_seal_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let block = seal_pointer_payload(&key, &nonce, 2, &owner(), &object());
        // Unseal claiming a different scope: the AAD recomputes and the tag fails.
        assert_eq!(
            open_pointer_payload(&key, 2, &[8; 16], &owner().verifying_key(), &block)
                .unwrap_err()
                .check(),
            "seal-open-failed"
        );
    }

    #[test]
    fn wrong_owner_key_fails_identity_signature() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let block = seal_pointer_payload(&key, &nonce, 2, &owner(), &object());
        let other = EcdsaSigner::from_scalar(&[0x31; 32])
            .unwrap()
            .verifying_key();
        assert_eq!(
            open_pointer_payload(&key, 2, &[7; 16], &other, &block)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    #[test]
    fn downgrade_v_fails_the_seal_tag() {
        let key = [3u8; KEY_LEN];
        let nonce = [9u8; NONCE_LEN];
        let block = seal_pointer_payload(&key, &nonce, 2, &owner(), &object());
        assert_eq!(
            open_pointer_payload(&key, 1, &[7; 16], &owner().verifying_key(), &block)
                .unwrap_err()
                .check(),
            "seal-open-failed"
        );
    }
}
