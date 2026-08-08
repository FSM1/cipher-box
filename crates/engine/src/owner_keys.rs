//! The owner's production [`OwnerScopeKeys`] arm over the session identity
//! (blueprint/engine.md "Rotation primitives").

use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SECRET_LEN;
use zeroize::Zeroizing;

use crate::net::rotation::OwnerScopeKeys;
use crate::session::SessionIdentity;

/// The two per-scope owner derivations a re-seal needs, resolved off the live
/// session.
///
/// Borrows the session rather than copying seeds out of it: a cascade discovers
/// its scope ids at runtime, so the derivations must stay lazy, and the session
/// stays the terminal owner of the secrets they come from.
#[allow(dead_code)]
pub(crate) struct OwnerSessionKeys<'a> {
    session: &'a SessionIdentity,
}

#[allow(dead_code)]
impl<'a> OwnerSessionKeys<'a> {
    pub(crate) fn new(session: &'a SessionIdentity) -> Self {
        Self { session }
    }
}

impl OwnerScopeKeys for OwnerSessionKeys<'_> {
    fn writer_pseudonym(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
        self.session.owner_writer_pseudonym_signer(scope_id)
    }

    fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(*self.session.pointer_read_key(scope_id).as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::kdf;
    use cipherbox_core::suite::secret::ct_eq;

    use crate::facade::LoginSecret;

    const SECRET: [u8; 32] = [0x11; 32];
    const SCOPE: [u8; 16] = [0x22; 16];

    fn session() -> SessionIdentity {
        SessionIdentity::derive(&LoginSecret::new(SECRET.to_vec())).expect("valid identity")
    }

    fn pseudonym_from(seed: &[u8; 32]) -> [u8; 32] {
        kdf::pseudonym_sign(seed, &SCOPE).verifying_key().to_bytes()
    }

    #[test]
    fn writer_pseudonym_is_the_owner_pseudonym_seed_edge() {
        let session = session();
        let keys = OwnerSessionKeys::new(&session);
        assert_eq!(
            keys.writer_pseudonym(&SCOPE).verifying_key().to_bytes(),
            pseudonym_from(kdf::owner_pseudonym_seed(&SECRET).as_bytes()),
        );
    }

    /// None of the three inputs FSM1/cipher-box-next ADR 0005 rejected may
    /// stand in for `ownerPseudonymSeed` (why it is unrecoverable:
    /// [`SessionIdentity::owner_writer_pseudonym_signer`]).
    #[test]
    fn writer_pseudonym_is_none_of_the_rejected_owner_inputs() {
        let session = session();
        let keys = OwnerSessionKeys::new(&session);
        let live = keys.writer_pseudonym(&SCOPE).verifying_key().to_bytes();

        let enc = kdf::enc_subkey(&SECRET);
        let self_ecdh = enc
            .diffie_hellman(&enc.public())
            .expect("self-ECDH is contributory");

        for (name, seed) in [
            ("the login secret", SECRET),
            (
                "the owner pointer seed",
                *kdf::owner_pointer_seed(&SECRET).as_bytes(),
            ),
            ("self-ECDH over the enc subkey", *self_ecdh.as_bytes()),
        ] {
            assert_ne!(live, pseudonym_from(&seed), "{name} stood in for the edge");
        }
    }

    #[test]
    fn pointer_read_key_is_the_sessions_per_scope_key() {
        let session = session();
        let keys = OwnerSessionKeys::new(&session);
        assert!(ct_eq(
            &keys.pointer_read_key(&SCOPE),
            session.pointer_read_key(&SCOPE).as_bytes(),
        ));
    }

    #[test]
    fn both_derivations_are_keyed_by_the_scope() {
        let session = session();
        let keys = OwnerSessionKeys::new(&session);
        let other = [0x33u8; 16];
        assert_ne!(
            keys.writer_pseudonym(&SCOPE).verifying_key().to_bytes(),
            keys.writer_pseudonym(&other).verifying_key().to_bytes(),
        );
        assert!(!ct_eq(
            &keys.pointer_read_key(&SCOPE),
            &keys.pointer_read_key(&other),
        ));
    }
}
