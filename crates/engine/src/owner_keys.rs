//! The owner's production [`OwnerScopeKeys`] arm over the session identity
//! (blueprint/engine.md "Rotation primitives").

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::{SECRET_LEN, SecretBytes};
use zeroize::Zeroizing;

use crate::net::rotation::OwnerScopeKeys;
use crate::session::SessionIdentity;
use crate::sync::pointer::scope_pointer_name;

/// The two per-scope owner derivations a re-seal needs, resolved off the live
/// session.
///
/// Borrows the session rather than copying seeds out of it: a cascade discovers
/// its scope ids at runtime, so the derivations must stay lazy, and the session
/// stays the terminal owner of the secrets they come from.
pub(crate) struct OwnerSessionKeys<'a> {
    session: &'a SessionIdentity,
}

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

    fn pointer_name(&self, scope_id: &[u8; 16]) -> IpnsName {
        scope_pointer_name(self.session.owner_pointer_seed().as_bytes(), scope_id)
    }
}

/// The same derivations over **owned** seeds, for the spawned sweep task,
/// which is polled after every borrow of the session has ended.
///
/// Two seeds and no wider capability: the login secret and the identity signer
/// stay behind.
pub(crate) struct OwnerSeedKeys {
    pseudonym_seed: SecretBytes,
    pointer_seed: SecretBytes,
}

impl OwnerSeedKeys {
    pub(crate) fn of(session: &SessionIdentity) -> Self {
        Self {
            pseudonym_seed: session.owner_pseudonym_seed(),
            pointer_seed: session.owner_pointer_seed(),
        }
    }
}

impl OwnerScopeKeys for OwnerSeedKeys {
    fn writer_pseudonym(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
        kdf::pseudonym_sign(self.pseudonym_seed.as_bytes(), scope_id)
    }

    fn pointer_read_key(&self, scope_id: &[u8; 16]) -> Zeroizing<[u8; SECRET_LEN]> {
        Zeroizing::new(*kdf::pointer_read_key(self.pointer_seed.as_bytes(), scope_id).as_bytes())
    }

    fn pointer_name(&self, scope_id: &[u8; 16]) -> IpnsName {
        scope_pointer_name(self.pointer_seed.as_bytes(), scope_id)
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
    /// The spawned sweep signs under the owned arm while every other rotation
    /// signs under the borrowed one, and a scope's `ownerPseudonymPk` is
    /// committed epoch-free and never revised — so a divergence between them is
    /// a permanent `SignerNotCommitted` on every later rotation of that scope,
    /// discoverable only in production.
    #[test]
    fn the_owned_arm_reproduces_the_session_arm_for_every_scope() {
        let session = session();
        let borrowed = OwnerSessionKeys::new(&session);
        let owned = OwnerSeedKeys::of(&session);

        for scope in [[0x00u8; 16], SCOPE, [0xff; 16]] {
            assert_eq!(
                borrowed.writer_pseudonym(&scope).verifying_key().to_bytes(),
                owned.writer_pseudonym(&scope).verifying_key().to_bytes(),
                "the two arms must name one committed pseudonym per scope",
            );
            assert!(ct_eq(
                &borrowed.pointer_read_key(&scope),
                &owned.pointer_read_key(&scope),
            ));
        }
    }

    /// The name the sweep's pointer consult addresses is the one the session's
    /// own pointer seed derives, not one from a per-scope key derived from it.
    #[test]
    fn the_owned_arm_names_the_sessions_scope_pointer() {
        let session = session();
        let owned = OwnerSeedKeys::of(&session);
        assert_eq!(
            owned.pointer_name(&SCOPE),
            scope_pointer_name(kdf::owner_pointer_seed(&SECRET).as_bytes(), &SCOPE),
        );
    }

    /// A consult holds no value a scope-pointer record could be signed with:
    /// the name is the only pointer edge either arm exposes.
    #[test]
    fn both_arms_name_one_scope_pointer_per_scope() {
        let session = session();
        let borrowed = OwnerSessionKeys::new(&session);
        let owned = OwnerSeedKeys::of(&session);

        for scope in [[0x00u8; 16], SCOPE, [0xff; 16]] {
            assert_eq!(borrowed.pointer_name(&scope), owned.pointer_name(&scope));
        }
        assert_ne!(owned.pointer_name(&SCOPE), owned.pointer_name(&[0x33; 16]));
    }
}
