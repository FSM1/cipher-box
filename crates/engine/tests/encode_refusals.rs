//! Encode-side refusals of the engine's own formats (AGENTS.md rule 8). CI also
//! runs this file under `--release`, where `debug_assert!` is compiled out, so
//! a refusal that leans on one fails there.

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ecdsa::SIGNATURE_LEN;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_engine::grants::{InviteError, InviteFragment, MAX_INVITE_FRAGMENT_BYTES};

/// The decoder refuses a fragment past its bound, so the encoder refuses to
/// produce one: an owner contact code of the whole bound leaves no room.
#[test]
fn a_fragment_whose_contact_code_fills_the_bound_is_refused_at_encode() {
    let fragment = InviteFragment {
        invite_secret: SecretBytes::new([0x4e; 32]),
        owner_contact_code: vec![0xa5; MAX_INVITE_FRAGMENT_BYTES],
        scope_id: [0x5c; 16],
        scope_pointer_name: IpnsName::from_public_key(
            &Ed25519Signer::from_seed([0x5d; 32]).verifying_key(),
        ),
        pointer_read_key: SecretBytes::new([0x66; 32]),
        owner_name: String::new(),
        folder_name: "Photos".to_owned(),
        names_sig: [0; SIGNATURE_LEN],
    };
    assert_eq!(
        fragment.encode().map(|_| ()),
        Err(InviteError::FragmentTooLarge)
    );
}
