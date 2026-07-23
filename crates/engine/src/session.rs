//! Cold-start session identity — the seed-derived signing and sealing identity
//! assembled once at [`Engine::start`](crate::facade::Engine::start).
//!
//! The cold-start sequence begins by deriving, as a pure function of the login
//! secret, the owner-plane identity that needs no network: the encryption
//! subkey, the owner pointer seed, and the vault-pointer signer chain
//! (blueprint/engine.md "Pointer planes"; CONTEXT.md "Vault pointer", "Scope
//! pointer", "Encryption subkey"). Per-scope read/write material and the
//! per-name write-plane signers layer on top through the factory methods here,
//! fed the scope seeds the resolve/gate path unseals later — this module owns
//! the derivation edges, the resolve slices (#745/#746) and the liveness
//! composition (#750/#751) own the inputs.
//!
//! Every derivation composes `crates/core`'s frozen KDF edge catalog
//! ([`cipherbox_core::kdf`]); nothing here derives a key of its own. The whole
//! type is a pure function of the injected secret — no clock, no RNG — so the
//! same secret always yields the same identity (the determinism a cold-start
//! test pins). Secret material lives in zeroizing owners and is redacted from
//! `Debug`; the login secret is retained in engine memory only, because the
//! vault-pointer chain is index-probed at runtime (cold start and per tick,
//! CONTEXT.md "Vault pointer") and cannot be fully pre-derived.

use core::fmt;

use cipherbox_core::kdf;
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use zeroize::Zeroizing;

use crate::facade::LoginSecret;

/// The session's seed-derived identity — the single place derived key material
/// lives once the engine is live.
///
/// Constructed by [`SessionIdentity::derive`] at cold start and held by the
/// engine for the session's lifetime. Public-key accessors are `pub`; the
/// signer/seal factories that return secret-bearing material are `pub(crate)`,
/// reachable only by the in-crate pipeline (resolve, publish, rotation, the
/// liveness loop) — hosts wrap the facade and never hold signers.
// The factory surface is the hook the deferred slices consume (resolve
// #745/#746, liveness composition #750/#751, rotation); `derive` is live at
// cold start now, the readers of each factory land with those slices.
#[allow(dead_code)]
pub(crate) struct SessionIdentity {
    /// The login secret, retained for the runtime vault-pointer index probe.
    /// Engine memory only: never persisted, never logged, zeroized on drop.
    login_secret: Zeroizing<Vec<u8>>,
    /// The user's X25519 encryption subkey (`enc-subkey` edge). Seals only;
    /// the identity key signs. Zeroizes on drop.
    enc_subkey: X25519Secret,
    /// The owner pointer seed (`owner-pointer-seed` edge). Per-scope pointer
    /// signers and pointer read keys derive from it lazily. Zeroizes on drop.
    owner_pointer_seed: SecretBytes,
}

#[allow(dead_code)]
impl SessionIdentity {
    /// Derive the cold-start identity from the login secret — a pure function
    /// of the secret bytes (no clock, no RNG), composing only frozen catalog
    /// edges. Same secret in, same identity out.
    pub(crate) fn derive(secret: &LoginSecret) -> Self {
        let bytes = secret.expose();
        Self {
            login_secret: Zeroizing::new(bytes.to_vec()),
            enc_subkey: kdf::enc_subkey(bytes),
            owner_pointer_seed: kdf::owner_pointer_seed(bytes),
        }
    }

    /// The public half of the encryption subkey — the sealing identity peers
    /// address. Non-secret; safe to publish and to compare in tests.
    pub fn enc_subkey_public(&self) -> X25519Public {
        self.enc_subkey.public()
    }

    /// The retained login secret, for the runtime vault-pointer index probe
    /// (cold start and per tick). Owner-plane name/read-key derivation happens
    /// inside the pointer walk, which needs the raw secret; secret-bearing, so
    /// in-crate only.
    pub(crate) fn login_secret(&self) -> &[u8] {
        &self.login_secret
    }

    /// The encryption subkey itself — the sealing key the grant/mailbox paths
    /// use. Secret-bearing, so in-crate only.
    pub(crate) fn enc_subkey(&self) -> &X25519Secret {
        &self.enc_subkey
    }

    /// The `i`-th vault-pointer signer (`vault-pointer-index` edge): the
    /// per-name Ed25519 signer for the indexed owner re-point chain, index 0
    /// the default. Probed one past the highest known on cold start and per
    /// tick (CONTEXT.md "Vault pointer"), so it derives on demand.
    pub(crate) fn vault_pointer_signer(&self, index: u64) -> Ed25519Signer {
        kdf::vault_pointer_index(&self.login_secret, index)
    }

    /// The per-scope pointer signer (`scope-pointer` edge): the owner-keyed
    /// stable IPNS name a shared scope carries, from the owner pointer seed
    /// and the scope id.
    pub(crate) fn scope_pointer_signer(&self, scope_id: &[u8; 16]) -> Ed25519Signer {
        kdf::scope_pointer(self.owner_pointer_seed.as_bytes(), scope_id)
    }

    /// The stable per-scope pointer read key (`pointer-read-key` edge) that
    /// seals a scope's re-point object.
    pub(crate) fn pointer_read_key(&self, scope_id: &[u8; 16]) -> SecretBytes {
        kdf::pointer_read_key(self.owner_pointer_seed.as_bytes(), scope_id)
    }

    /// The per-name write-plane IPNS signer for a node: `writeSeed(node) =
    /// KDF(writeScopeSeed, node.id)` then the `ipns-keypair` edge. This is the
    /// per-name `Ed25519Signer` the held set stores for its sub-EOL `seq+1`
    /// renewal (#750/#751) — the resolve/gate path supplies the unsealed
    /// `write_scope_seed`. Keyed solely by its arguments (no session field), so
    /// it is an associated function the held-set insert can call directly.
    pub(crate) fn write_name_signer(
        write_scope_seed: &[u8; 32],
        node_id: &[u8; 16],
    ) -> Ed25519Signer {
        let write_seed = kdf::write_seed(write_scope_seed, node_id);
        kdf::ipns_keypair(write_seed.as_bytes())
    }

    /// The writer-pseudonym signer (`pseudonym-sign` edge): the per-(scope,
    /// writer) signing keypair the rotator detached-signs re-sealed structures
    /// with, from the pairwise material (owner root secret or grant ECDH) and
    /// the scope id. The pairwise material already fully encodes the
    /// owner/writer identity, so — unlike every sibling factory — this one
    /// consults no stored session field; its output is keyed solely by its
    /// arguments.
    pub(crate) fn writer_pseudonym_signer(
        &self,
        pairwise_material: &[u8; 32],
        scope_id: &[u8; 16],
    ) -> Ed25519Signer {
        kdf::pseudonym_sign(pairwise_material, scope_id)
    }
}

impl fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionIdentity(redacted)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_util::ct_eq_32;

    fn identity(secret: &[u8]) -> SessionIdentity {
        SessionIdentity::derive(&LoginSecret::new(secret.to_vec()))
    }

    #[test]
    fn derivation_is_a_pure_function_of_the_secret() {
        let a = identity(&[7u8; 32]);
        let b = identity(&[7u8; 32]);
        let scope = [3u8; 16];
        let node = [4u8; 16];
        let write_scope_seed = [5u8; 32];

        assert_eq!(
            a.enc_subkey_public().to_bytes(),
            b.enc_subkey_public().to_bytes(),
            "same secret must yield the same enc subkey"
        );
        assert_eq!(
            a.vault_pointer_signer(0).verifying_key().to_bytes(),
            b.vault_pointer_signer(0).verifying_key().to_bytes(),
            "same secret must yield the same vault-pointer signer"
        );
        assert_eq!(
            a.scope_pointer_signer(&scope).verifying_key().to_bytes(),
            b.scope_pointer_signer(&scope).verifying_key().to_bytes(),
        );
        assert!(
            ct_eq_32(
                a.pointer_read_key(&scope).as_bytes(),
                b.pointer_read_key(&scope).as_bytes(),
            ),
            "same secret must yield the same pointer read key",
        );
        assert_eq!(
            SessionIdentity::write_name_signer(&write_scope_seed, &node)
                .verifying_key()
                .to_bytes(),
            SessionIdentity::write_name_signer(&write_scope_seed, &node)
                .verifying_key()
                .to_bytes(),
            "the per-name write signer is a pure function of seed + node id",
        );
    }

    #[test]
    fn a_different_secret_yields_a_different_identity() {
        let a = identity(&[7u8; 32]);
        let b = identity(&[8u8; 32]);

        assert_ne!(
            a.enc_subkey_public().to_bytes(),
            b.enc_subkey_public().to_bytes(),
        );
        assert_ne!(
            a.vault_pointer_signer(0).verifying_key().to_bytes(),
            b.vault_pointer_signer(0).verifying_key().to_bytes(),
        );
        assert_ne!(
            a.scope_pointer_signer(&[3u8; 16])
                .verifying_key()
                .to_bytes(),
            b.scope_pointer_signer(&[3u8; 16])
                .verifying_key()
                .to_bytes(),
            "the owner-plane scope pointer is keyed off the login secret",
        );
    }

    #[test]
    fn the_vault_pointer_chain_is_indexed() {
        let id = identity(&[7u8; 32]);
        assert_ne!(
            id.vault_pointer_signer(0).verifying_key().to_bytes(),
            id.vault_pointer_signer(1).verifying_key().to_bytes(),
            "each index is a distinct name in the chain",
        );
    }

    #[test]
    fn per_name_write_signers_bind_scope_seed_and_node_id() {
        let base = SessionIdentity::write_name_signer(&[5u8; 32], &[4u8; 16])
            .verifying_key()
            .to_bytes();
        assert_ne!(
            base,
            SessionIdentity::write_name_signer(&[6u8; 32], &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different write scope seed is a different name",
        );
        assert_ne!(
            base,
            SessionIdentity::write_name_signer(&[5u8; 32], &[9u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different node id is a different name",
        );
    }

    #[test]
    fn writer_pseudonym_signer_binds_pairwise_material_and_scope() {
        let id = identity(&[7u8; 32]);
        let pairwise = [2u8; 32];
        let scope = [3u8; 16];
        let base = id
            .writer_pseudonym_signer(&pairwise, &scope)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            base,
            id.writer_pseudonym_signer(&pairwise, &scope)
                .verifying_key()
                .to_bytes(),
            "same pairwise material and scope must yield the same pseudonym signer",
        );
        assert_ne!(
            base,
            id.writer_pseudonym_signer(&[9u8; 32], &scope)
                .verifying_key()
                .to_bytes(),
            "different pairwise material is a different pseudonym",
        );
        assert_ne!(
            base,
            id.writer_pseudonym_signer(&pairwise, &[4u8; 16])
                .verifying_key()
                .to_bytes(),
            "a different scope is a different pseudonym",
        );
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(
            format!("{:?}", identity(&[7u8; 32])),
            "SessionIdentity(redacted)"
        );
    }
}
