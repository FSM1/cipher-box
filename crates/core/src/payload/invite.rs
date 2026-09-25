//! The owner signature over the names an invite-link fragment carries
//! (blueprint/core.md "Invite fragment and claim", ADR 0027 D5).
//!
//! The fragment is plain det-CBOR with no MAC, and its names do not depend on
//! the invite secret, so without this signature a forwarder could relabel a
//! working link. The engine owns the fragment codec; core owns the signed
//! preimage, so both hosts verify the same bytes.

use crate::codec::scrub::ScrubOnDrop;
use crate::codec::{Value, encode_fixed_depth};
use crate::error::{CodecError, TrustViolation};
use crate::ipns::IpnsName;
use crate::suite::ecdsa::{EcdsaSignature, EcdsaSigner, EcdsaVerifier};

/// The domain string the invite-names preimage leads with.
pub const INVITE_NAMES_SIG_DOMAIN: &str = "cipherbox/v2/invite-names-sig";

/// The names a link's owner signs: the scope pointer the link reads through,
/// and the two labels the invite page shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InviteNames<'a> {
    /// The scope pointer name the fragment carries.
    pub scope_pointer_name: &'a IpnsName,
    /// The owner's name, as the owner chose it. May be empty.
    pub owner_name: &'a str,
    /// The shared folder's name.
    pub folder_name: &'a str,
}

/// The det-CBOR preimage the owner identity signs over the names:
/// `[INVITE_NAMES_SIG_DOMAIN, scopePointerName, ownerName, folderName]`. The
/// leading domain string keeps it apart from every other owner-signed family.
pub fn invite_names_preimage(names: &InviteNames<'_>) -> Vec<u8> {
    let mut tree = Value::Array(vec![
        Value::Text(INVITE_NAMES_SIG_DOMAIN.to_string()),
        Value::Text(names.scope_pointer_name.as_str().to_string()),
        Value::Text(names.owner_name.to_string()),
        Value::Text(names.folder_name.to_string()),
    ]);
    let guard = ScrubOnDrop(&mut tree);
    encode_fixed_depth(guard.0)
}

/// Sign `names` under the owner identity.
pub fn sign_invite_names(owner: &EcdsaSigner, names: &InviteNames<'_>) -> EcdsaSignature {
    owner.sign_detcbor(&invite_names_preimage(names))
}

/// Verify the owner signature over `names`. A mismatch is
/// [`TrustViolation::IdentitySignatureInvalid`].
pub fn verify_invite_names(
    owner: &EcdsaVerifier,
    names: &InviteNames<'_>,
    signature: &EcdsaSignature,
) -> Result<(), CodecError> {
    if owner.verify_detcbor(&invite_names_preimage(names), signature) {
        Ok(())
    } else {
        Err(TrustViolation::IdentitySignatureInvalid.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::ed25519::Ed25519Signer;

    fn pointer_name() -> IpnsName {
        IpnsName::from_public_key(&Ed25519Signer::from_seed([0x51; 32]).verifying_key())
    }

    fn owner() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x21; 32]).expect("valid scalar")
    }

    #[test]
    fn the_names_verify_under_the_owner_and_under_no_one_else() {
        let pointer = pointer_name();
        let names = InviteNames {
            scope_pointer_name: &pointer,
            owner_name: "Ada",
            folder_name: "Photos",
        };
        let sig = sign_invite_names(&owner(), &names);
        assert!(verify_invite_names(&owner().verifying_key(), &names, &sig).is_ok());
        let stranger = EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar");
        assert_eq!(
            verify_invite_names(&stranger.verifying_key(), &names, &sig)
                .unwrap_err()
                .check(),
            "identity-signature-invalid"
        );
    }

    #[test]
    fn every_name_is_under_the_signature() {
        let pointer = pointer_name();
        let other_pointer =
            IpnsName::from_public_key(&Ed25519Signer::from_seed([0x52; 32]).verifying_key());
        let names = InviteNames {
            scope_pointer_name: &pointer,
            owner_name: "Ada",
            folder_name: "Photos",
        };
        let sig = sign_invite_names(&owner(), &names);
        for changed in [
            InviteNames {
                owner_name: "Eve",
                ..names
            },
            InviteNames {
                folder_name: "Taxes",
                ..names
            },
            InviteNames {
                scope_pointer_name: &other_pointer,
                ..names
            },
        ] {
            assert_eq!(
                verify_invite_names(&owner().verifying_key(), &changed, &sig)
                    .unwrap_err()
                    .check(),
                "identity-signature-invalid",
                "{changed:?}"
            );
        }
    }
}
