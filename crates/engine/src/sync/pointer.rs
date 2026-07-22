//! The pointer planes — scope pointer, vault pointer, re-point object, and the
//! consult discipline (blueprint/engine.md "Pointer planes"; CONTEXT.md
//! "Scope pointer", "Vault pointer", "Re-point object"; #38, #39 D5).
//!
//! Three planes (#38 D1): the owner plane (stable pointer names, owner-only
//! keys), the write plane (rotating derived names), the read plane (seeds).
//! The engine publishes to the owner plane **only in owner sessions**. Every
//! re-point object is owner-identity-signed and sealed under the scope's stable
//! `pointerReadKey`; core owns the codec, sign, and verify
//! ([`seal_pointer_payload`]/[`open_pointer_payload`]) — this module owns name
//! derivation, the vault-pointer index walk, the owner-plane write gate, and
//! the consult discipline. The floor cold-seed itself is the floor law's
//! ([`floor::cold_seed_checked`](crate::gate::floor::cold_seed_checked)) — cold
//! start feeds it the re-point this walk authenticated.
//!
//! **Consult discipline: polled, not fallback** (#38 D4). A revokee's forged
//! old-epoch record passes every *other* gate stage (valid old-key signature,
//! fresh sequence, floor-level epoch, old-seed unseal), so staleness never
//! fires and a fallback-only pointer would never be consulted. The pointer
//! resolve therefore *joins the focus-window tick* for open shared scopes,
//! runs on access for cached ones, and is the first act on cold start — it is
//! never gated behind a staleness signal.

use cipherbox_core::error::CodecError;
use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::payload::{RepointObject, open_pointer_payload, seal_pointer_payload};
use cipherbox_core::suite::aead::NONCE_LEN;
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};

use crate::entropy::{Entropy, EntropyError};
use crate::seams::{SeamError, SeamResult};

/// A safety bound on the vault-pointer index walk. The chain length is
/// owner-authored (each index needs the owner's identity signature to open),
/// so a valid chain is finite; this only guards against a misbehaving fetch
/// never returning "unresolvable".
const MAX_VAULT_POINTER_PROBE: u64 = 1 << 16;

/// Who is driving this session — the owner-plane write gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRole {
    /// The vault owner: may publish the owner plane (scope/vault pointers).
    Owner,
    /// A grantee: reads pointers, never publishes the owner plane.
    Grantee,
}

/// Why the pointer plane is being consulted — always polled, never a staleness
/// fallback (#38 D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsultReason {
    /// The first act on cold start (before any record adoption).
    ColdStart,
    /// Riding the focus-window tick for an open shared scope.
    FocusTick,
    /// On access to a cached shared scope past its staleness threshold.
    OnAccess,
}

/// A pointer-plane operation failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PointerError {
    /// An owner-plane publish was attempted from a non-owner session.
    NotOwnerSession,
    /// Entropy acquisition for the seal nonce failed (fail-closed).
    Entropy(EntropyError),
    /// A fetched pointer block failed to open — tamper, wrong owner, scope
    /// transplant, or version downgrade (surfaced from core verbatim).
    Open(CodecError),
    /// A host durable-store / transport seam failure.
    Seam(SeamError),
}

/// Fetches the sealed re-point block published at a pointer name. `None` means
/// the name is unresolvable (a gap in the vault-pointer chain, or a scope with
/// no pointer yet). Abstracts the record resolve + content fetch the net/
/// content slices own, so the pointer walk is testable in isolation.
pub trait PointerFetch {
    /// The sealed re-point block at `name`, or `None` if unresolvable.
    async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>>;
}

/// The vault-pointer IPNS name at `index` (`pointerKey_i = KDF(secret,
/// "vault-pointer" ‖ i)`, CONTEXT.md).
pub fn vault_pointer_name(login_secret: &[u8], index: u64) -> IpnsName {
    IpnsName::from_public_key(&kdf::vault_pointer_index(login_secret, index).verifying_key())
}

/// The scope-pointer IPNS name for a shared scope (`pointerKey(scope) =
/// KDF(ownerPointerSeed, scope.id)`, CONTEXT.md). The signer for that name is
/// [`scope_pointer_signer`].
pub fn scope_pointer_name(owner_pointer_seed: &[u8; 32], scope_id: &[u8; 16]) -> IpnsName {
    IpnsName::from_public_key(&kdf::scope_pointer(owner_pointer_seed, scope_id).verifying_key())
}

/// The Ed25519 signer for a scope pointer's IPNS record (owner-only).
pub fn scope_pointer_signer(
    owner_pointer_seed: &[u8; 32],
    scope_id: &[u8; 16],
) -> cipherbox_core::suite::ed25519::Ed25519Signer {
    kdf::scope_pointer(owner_pointer_seed, scope_id)
}

/// One adopted vault-pointer index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPointerAdoption {
    /// The highest valid index adopted.
    pub index: u64,
    /// Its owner-signed re-point object.
    pub repoint: RepointObject,
}

/// Walk the indexed vault-pointer chain with probe-one-past semantics
/// (CONTEXT.md "Vault pointer", #39 D5): from index 0 upward, adopt the highest
/// index bearing a valid owner-signed payload, and stop at the first
/// unresolvable index — which only the owner can extend. Probing continues one
/// index past the highest resolvable one so an owner-side index bump (the
/// pointer-key-compromise recovery) is discovered.
///
/// A resolvable-but-invalid payload (bad owner signature, tamper) stops the
/// walk fail-closed at that index: it is never adopted and the walk never
/// reaches beyond it, so a forged record cannot truncate the chain *below* an
/// already-adopted valid index.
///
/// `login_secret` is a read-only borrow; sole consumer; zeroized at the session owner.
pub async fn resolve_vault_pointer<F: PointerFetch>(
    fetch: &F,
    login_secret: &[u8],
    owner_identity: &EcdsaVerifier,
    root_scope_id: &[u8; 16],
    payload_version: u64,
) -> Result<Option<VaultPointerAdoption>, PointerError> {
    let owner_seed = kdf::owner_pointer_seed(login_secret);
    let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), root_scope_id);

    let mut best: Option<VaultPointerAdoption> = None;
    let mut index = 0u64;
    while index < MAX_VAULT_POINTER_PROBE {
        let name = vault_pointer_name(login_secret, index);
        match fetch.fetch(&name).await.map_err(PointerError::Seam)? {
            // A gap: the chain ends here; the highest adopted below is the answer.
            None => break,
            Some(block) => match open_repoint(
                read_key.as_bytes(),
                payload_version,
                root_scope_id,
                owner_identity,
                &block,
            ) {
                Ok(repoint) => {
                    best = Some(VaultPointerAdoption { index, repoint });
                    index += 1;
                }
                // Fail-closed: an invalid payload is never adopted and stops the
                // walk (a forged record cannot extend or masquerade the chain).
                Err(e) => return Err(e),
            },
        }
    }
    Ok(best)
}

/// Seal a re-point object for publication — **owner sessions only** (owner-
/// plane write gate, #38 D1). The nonce is drawn from injected entropy
/// (determinism law); the returned bytes are the sealed block to publish at the
/// pointer name. A non-owner session is fail-closed with
/// [`PointerError::NotOwnerSession`].
pub fn seal_repoint(
    session: SessionRole,
    entropy: &mut dyn Entropy,
    pointer_read_key: &[u8; 32],
    payload_version: u64,
    owner_signer: &EcdsaSigner,
    object: &RepointObject,
) -> Result<Vec<u8>, PointerError> {
    if session != SessionRole::Owner {
        return Err(PointerError::NotOwnerSession);
    }
    let mut nonce = [0u8; NONCE_LEN];
    entropy.fill(&mut nonce).map_err(PointerError::Entropy)?;
    Ok(seal_pointer_payload(
        pointer_read_key,
        &nonce,
        payload_version,
        owner_signer,
        object,
    ))
}

/// Open an authenticated re-point object from a fetched pointer block (the
/// consult read path). A verify failure surfaces core's verdict verbatim —
/// fail-closed, never reclassified as staleness.
pub fn open_repoint(
    pointer_read_key: &[u8; 32],
    payload_version: u64,
    scope_id: &[u8; 16],
    owner_identity: &EcdsaVerifier,
    block: &[u8],
) -> Result<RepointObject, PointerError> {
    open_pointer_payload(
        pointer_read_key,
        payload_version,
        scope_id,
        owner_identity,
        block,
    )
    .map_err(PointerError::Open)
}

/// Whether to consult the scope pointer now — the polled discipline, decided
/// independently of any staleness signal. Consult on cold start, on the focus
/// tick for an open shared scope, and on access to a cached shared scope past
/// staleness. Never a staleness fallback (a forged old-epoch record that passes
/// staleness must not suppress the consult, #38 D4).
pub fn should_consult(
    is_cold_start: bool,
    is_open_shared_scope: bool,
    accessed_past_staleness: bool,
) -> Option<ConsultReason> {
    if is_cold_start {
        Some(ConsultReason::ColdStart)
    } else if is_open_shared_scope {
        Some(ConsultReason::FocusTick)
    } else if accessed_past_staleness {
        Some(ConsultReason::OnAccess)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::testkit::{SeededEntropy, block_on};

    // A deterministic owner identity for the fixtures.
    fn owner_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[3u8; 32]).expect("valid scalar")
    }

    /// A scripted pointer network: names → sealed blocks; unknown names are
    /// unresolvable (chain gaps).
    #[derive(Clone, Default)]
    struct ScriptedPointers {
        blocks: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl ScriptedPointers {
        fn put(&self, name: &IpnsName, block: Vec<u8>) {
            self.blocks
                .lock()
                .unwrap()
                .insert(name.as_str().to_owned(), block);
        }
    }

    impl PointerFetch for ScriptedPointers {
        async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
            Ok(self.blocks.lock().unwrap().get(name.as_str()).cloned())
        }
    }

    fn repoint(scope_id: [u8; 16], min_read_epoch: u64, write_epoch: u64) -> RepointObject {
        RepointObject {
            scope_id,
            current_root: vault_pointer_name(b"root-name-seed", 0),
            write_epoch,
            min_read_epoch,
            prev_root: None,
        }
    }

    const SECRET: &[u8] = b"login-secret-fixture-bytes";
    const ROOT_SCOPE: [u8; 16] = [0u8; 16];

    fn seal_index(
        pointers: &ScriptedPointers,
        owner: &EcdsaSigner,
        index: u64,
        object: &RepointObject,
    ) {
        let owner_seed = kdf::owner_pointer_seed(SECRET);
        let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &ROOT_SCOPE);
        let mut entropy = SeededEntropy::new(index);
        let block = seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            read_key.as_bytes(),
            1,
            owner,
            object,
        )
        .unwrap();
        pointers.put(&vault_pointer_name(SECRET, index), block);
    }

    #[test]
    fn owner_plane_seal_is_gated_to_owner_sessions() {
        let mut entropy = SeededEntropy::new(9);
        let owner_seed = kdf::owner_pointer_seed(SECRET);
        let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &ROOT_SCOPE);
        let err = seal_repoint(
            SessionRole::Grantee,
            &mut entropy,
            read_key.as_bytes(),
            1,
            &owner_signer(),
            &repoint(ROOT_SCOPE, 1, 1),
        )
        .expect_err("a grantee never writes the owner plane");
        assert_eq!(err, PointerError::NotOwnerSession);
    }

    #[test]
    fn vault_pointer_walk_adopts_the_highest_valid_index() {
        let pointers = ScriptedPointers::default();
        let owner = owner_signer();
        // The owner authored indices 0, 1, 2; index 3 is a gap.
        seal_index(&pointers, &owner, 0, &repoint(ROOT_SCOPE, 1, 1));
        seal_index(&pointers, &owner, 1, &repoint(ROOT_SCOPE, 2, 1));
        seal_index(&pointers, &owner, 2, &repoint(ROOT_SCOPE, 3, 2));

        let adopted = block_on(resolve_vault_pointer(
            &pointers,
            SECRET,
            &owner.verifying_key(),
            &ROOT_SCOPE,
            1,
        ))
        .unwrap()
        .expect("a valid chain adopts");
        assert_eq!(adopted.index, 2, "the highest valid index wins");
        assert_eq!(adopted.repoint.min_read_epoch, 3);
    }

    #[test]
    fn empty_chain_adopts_nothing() {
        let pointers = ScriptedPointers::default();
        let adopted = block_on(resolve_vault_pointer(
            &pointers,
            SECRET,
            &owner_signer().verifying_key(),
            &ROOT_SCOPE,
            1,
        ))
        .unwrap();
        assert_eq!(adopted, None, "cold start with no pointer adopts nothing");
    }

    #[test]
    fn a_forged_index_stops_the_walk_fail_closed() {
        let pointers = ScriptedPointers::default();
        let owner = owner_signer();
        seal_index(&pointers, &owner, 0, &repoint(ROOT_SCOPE, 1, 1));
        // Index 1 is sealed by a DIFFERENT (rogue) identity: it must not open
        // under the real owner and must fail the walk closed.
        let rogue = EcdsaSigner::from_scalar(&[7u8; 32]).unwrap();
        seal_index(&pointers, &rogue, 1, &repoint(ROOT_SCOPE, 99, 99));

        let owner_identity = owner.verifying_key();
        let result = resolve_vault_pointer(&pointers, SECRET, &owner_identity, &ROOT_SCOPE, 1);
        let err = block_on(result).expect_err("a forged index is fail-closed");
        assert!(matches!(err, PointerError::Open(_)));
    }

    #[test]
    fn consult_is_polled_not_a_staleness_fallback() {
        // Cold start and the focus tick consult regardless of any staleness.
        assert_eq!(
            should_consult(true, false, false),
            Some(ConsultReason::ColdStart)
        );
        assert_eq!(
            should_consult(false, true, false),
            Some(ConsultReason::FocusTick)
        );
        assert_eq!(
            should_consult(false, false, true),
            Some(ConsultReason::OnAccess)
        );
        // A closed, fresh, cached scope is not consulted this tick.
        assert_eq!(should_consult(false, false, false), None);
    }

    #[test]
    fn scope_pointer_name_and_signer_agree_and_the_re_point_round_trips() {
        let owner = owner_signer();
        let scope: [u8; 16] = [9u8; 16];
        let owner_seed = kdf::owner_pointer_seed(SECRET);

        // The scope-pointer signer's public key IS the scope-pointer name — the
        // signer is exactly the key that signs records published at that name.
        let name = scope_pointer_name(owner_seed.as_bytes(), &scope);
        let signer = scope_pointer_signer(owner_seed.as_bytes(), &scope);
        assert_eq!(name, IpnsName::from_public_key(&signer.verifying_key()));

        // A re-point sealed under the scope's stable pointer-read-key round-trips
        // through the consult read path.
        let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &scope);
        let object = RepointObject {
            scope_id: scope,
            current_root: vault_pointer_name(b"some-root", 0),
            write_epoch: 2,
            min_read_epoch: 4,
            prev_root: None,
        };
        let mut entropy = SeededEntropy::new(5);
        let block = seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            read_key.as_bytes(),
            1,
            &owner,
            &object,
        )
        .unwrap();
        let opened = open_repoint(
            read_key.as_bytes(),
            1,
            &scope,
            &owner.verifying_key(),
            &block,
        )
        .unwrap();
        assert_eq!(opened.min_read_epoch, 4);
        assert_eq!(opened.write_epoch, 2);
    }
}
