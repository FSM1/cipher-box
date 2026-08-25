//! The production [`PointerFetch`]: resolve the sealed re-point block a pointer
//! name carries (blueprint/engine.md "Pointer planes").
//!
//! The re-point object is inlined as the IPNS record value at the pointer name
//! (CONTEXT.md "Re-point object"; `crates/core/src/payload/pointer.rs`), so this
//! touches no gateway — a fan-out GET + core verify yields the freshest
//! owner-signed record and its authenticated value is the block. The inner
//! unseal + owner-ECDSA verify is the walk's ([`open_repoint`]), fail-closed;
//! this returns raw authenticated bytes and re-classifies no trust.
//!
//! [`open_repoint`]: crate::sync::pointer::open_repoint

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::secret::SECRET_LEN;

use super::fanout::fanout_get_verify;
use super::rotation::OwnerScopeKeys;
use crate::gate::floor;
use crate::seams::{FloorStore, RecordTransport, SeamResult};
use crate::sync::pointer::{PointerFetch, open_repoint, scope_pointer_name};

/// The record-plane [`PointerFetch`]: resolves pointer names over the borrowed
/// [`RecordTransport`] seam. Holds no key material — a pure function of the
/// transport bytes.
pub struct RecordPointerFetch<'a, T> {
    transport: &'a T,
}

impl<'a, T> RecordPointerFetch<'a, T> {
    /// Wrap the borrowed `/routing/v1` transport as a pointer fetch.
    pub fn new(transport: &'a T) -> Self {
        Self { transport }
    }
}

impl<T: RecordTransport> PointerFetch for RecordPointerFetch<'_, T> {
    async fn fetch(&self, name: &IpnsName) -> SeamResult<Option<Vec<u8>>> {
        let Some((verified, _bytes)) = fanout_get_verify(self.transport, name).await else {
            return Ok(None);
        };
        Ok(Some(verified.value))
    }
}

/// Why a consult produced no fresher name, on rule 6's axis: a rejection is a
/// fail-closed trust violation, a seam failure is availability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PointerConsultError {
    /// A transport or floor-store failure — retryable, never a trust verdict.
    Unavailable,
    /// The re-point did not authenticate, or vouched a rolled-back write epoch.
    Rejected,
}

/// One scope-pointer consult: fetch the block, authenticate the re-point,
/// refuse a rolled-back write epoch, then advance the write-epoch floor on
/// sight (floor law item 3, #38 D4).
///
/// Shared by both triggers the pointer discipline names — the sweep's
/// `Superseded` verdict and the focus tick's polled leg — so the trust rules a
/// consult enforces cannot differ between them.
pub(crate) struct PointerConsult<'a> {
    /// Derives the scope-pointer name (owner-only material, never published).
    pub owner_pointer_seed: &'a [u8; SECRET_LEN],
    /// The per-scope `pointer-read-key` derivation, and no wider capability.
    pub scope_keys: &'a dyn OwnerScopeKeys,
    /// The owner identity every re-point payload is signed under.
    pub owner_identity: &'a EcdsaVerifier,
    /// The pointer-payload envelope version a consulted re-point is read under.
    pub payload_version: u64,
    /// The session's vault anchor, which scopes the write-epoch regression
    /// stage. Filling it from anything but the session root mis-scopes it.
    pub session_root_scope_id: [u8; 16],
}

impl PointerConsult<'_> {
    /// The scope's current owner-vouched root name, or `None` when the scope was
    /// never re-pointed.
    pub(crate) async fn run<T: RecordTransport, F: FloorStore>(
        &self,
        transport: &T,
        floors: &F,
        scope_id: &[u8; 16],
    ) -> Result<Option<IpnsName>, PointerConsultError> {
        let pointer = scope_pointer_name(self.owner_pointer_seed, scope_id);
        let block = match RecordPointerFetch::new(transport).fetch(&pointer).await {
            Ok(Some(block)) => block,
            Ok(None) => return Ok(None),
            Err(_) => return Err(PointerConsultError::Unavailable),
        };
        let pointer_read_key = self.scope_keys.pointer_read_key(scope_id);
        let repoint = open_repoint(
            &pointer_read_key,
            self.payload_version,
            scope_id,
            self.owner_identity,
            &block,
        )
        .map_err(|_| PointerConsultError::Rejected)?;
        // Away from the vault anchor the scope pointer is the write-epoch
        // floor's only owner-vouched source, so a vouched epoch below it is a
        // rollback, not staleness (rule 6). The anchor's floor also answers to
        // the vault-pointer chain, so the two can legitimately diverge there —
        // the read stage's narrowing in `floor::repoint_regression`, inverted.
        if *scope_id != self.session_root_scope_id
            && floor::write_epoch_regression(floors, scope_id, repoint.write_epoch)
                .await
                .map_err(|_| PointerConsultError::Unavailable)?
                .is_some()
        {
            return Err(PointerConsultError::Rejected);
        }
        floor::advance_write_epoch_on_sight(floors, scope_id, repoint.write_epoch)
            .await
            .map_err(|_| PointerConsultError::Unavailable)?;
        Ok(Some(repoint.current_root))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::ipns::IpnsRecord;
    use cipherbox_core::kdf;
    use cipherbox_core::payload::RepointObject;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::seams::EndpointId;
    use crate::sync::pointer::{
        PointerError, SessionRole, resolve_vault_pointer, seal_repoint, vault_pointer_name,
    };
    use crate::testkit::fakes::InMemoryRecordStore;
    use crate::testkit::{SeededEntropy, block_on};

    const SECRET: &[u8] = b"login-secret-fixture-bytes";
    const ROOT_SCOPE: [u8; 16] = [0u8; 16];
    const PAYLOAD_VERSION: u64 = 1;
    const TTL_NANOS: u64 = 2_000_000_000;
    const EOL: &str = "2099-01-01T00:00:00Z";

    fn owner_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[3u8; 32]).expect("valid scalar")
    }

    fn repoint(min_read_epoch: u64, write_epoch: u64) -> RepointObject {
        RepointObject {
            scope_id: ROOT_SCOPE,
            current_root: vault_pointer_name(b"root-name-seed", 0),
            write_epoch,
            min_read_epoch,
            prev_root: None,
        }
    }

    /// Seal a re-point block under the root scope's stable pointer-read-key,
    /// owner-signed by `owner` (reuses the production `seal_repoint`).
    fn seal_block(owner: &EcdsaSigner, entropy_seed: u64, object: &RepointObject) -> Vec<u8> {
        let owner_seed = kdf::owner_pointer_seed(SECRET);
        let read_key = kdf::pointer_read_key(owner_seed.as_bytes(), &ROOT_SCOPE);
        let mut entropy = SeededEntropy::new(entropy_seed);
        seal_repoint(
            SessionRole::Owner,
            &mut entropy,
            read_key.as_bytes(),
            PAYLOAD_VERSION,
            owner,
            object,
        )
        .expect("owner session seals")
    }

    /// A valid IPNS record carrying `block` as its inlined value, signed by the
    /// vault-pointer key for `index` (so `verify(vault_pointer_name(index))`
    /// passes).
    fn record_for(index: u64, block: &[u8], sequence: u64) -> Vec<u8> {
        let signer = kdf::vault_pointer_index(SECRET, index);
        IpnsRecord::create_v2(&signer, block, sequence, TTL_NANOS, EOL).marshal()
    }

    fn endpoints(n: usize) -> Vec<EndpointId> {
        (0..n).map(|i| EndpointId::new(format!("e{i}"))).collect()
    }

    #[test]
    fn fetch_returns_the_inlined_repoint_value() {
        let eps = endpoints(1);
        let store = InMemoryRecordStore::new(eps.clone());
        let block = seal_block(&owner_signer(), 0, &repoint(1, 1));
        let name = vault_pointer_name(SECRET, 0);
        store.seed_record(&eps[0], name.as_str(), record_for(0, &block, 1));

        let fetch = RecordPointerFetch::new(&store);
        let got = block_on(fetch.fetch(&name)).expect("fetch succeeds");
        assert_eq!(
            got,
            Some(block),
            "the authenticated value is the inlined re-point block"
        );
    }

    #[test]
    fn fetch_unknown_name_is_none() {
        let eps = endpoints(2);
        let store = InMemoryRecordStore::new(eps);
        let fetch = RecordPointerFetch::new(&store);
        let unseeded = vault_pointer_name(SECRET, 7);
        assert_eq!(
            block_on(fetch.fetch(&unseeded)).expect("fetch succeeds"),
            None,
            "an unresolvable name yields None"
        );
    }

    #[test]
    fn fetch_prefers_the_freshest_valid_record() {
        let eps = endpoints(3);
        let store = InMemoryRecordStore::new(eps.clone());
        let name = vault_pointer_name(SECRET, 0);

        // Endpoint 0: an outer-signature-invalid copy (signed by the WRONG key) —
        // fan-out drops it as availability, never a trust verdict here.
        let stale_block = seal_block(&owner_signer(), 1, &repoint(2, 1));
        let wrong = kdf::vault_pointer_index(SECRET, 99);
        let forged_outer = IpnsRecord::create_v2(&wrong, &stale_block, 9, TTL_NANOS, EOL).marshal();
        store.seed_record(&eps[0], name.as_str(), forged_outer);

        // Endpoint 1: a valid, older-sequence copy.
        let older_block = seal_block(&owner_signer(), 2, &repoint(3, 1));
        store.seed_record(&eps[1], name.as_str(), record_for(0, &older_block, 2));

        // Endpoint 2: a valid, freshest copy — its value must win.
        let freshest_block = seal_block(&owner_signer(), 3, &repoint(5, 2));
        store.seed_record(&eps[2], name.as_str(), record_for(0, &freshest_block, 5));

        let fetch = RecordPointerFetch::new(&store);
        assert_eq!(
            block_on(fetch.fetch(&name)).expect("fetch succeeds"),
            Some(freshest_block),
            "the freshest valid record's value wins over an older one and a forged outer sig"
        );
    }

    #[test]
    fn production_fetch_walk_fails_closed_on_a_forged_inner_repoint() {
        let eps = endpoints(1);
        let store = InMemoryRecordStore::new(eps.clone());
        let owner = owner_signer();

        // Index 0: a valid owner-signed re-point.
        let good = seal_block(&owner, 0, &repoint(1, 1));
        store.seed_record(
            &eps[0],
            vault_pointer_name(SECRET, 0).as_str(),
            record_for(0, &good, 1),
        );
        // Index 1: a valid OUTER IPNS record whose INNER re-point is sealed by a
        // rogue owner identity — the outer passes fan-out verify, the inner
        // fails closed at the walk's `open_repoint`.
        let rogue = EcdsaSigner::from_scalar(&[7u8; 32]).unwrap();
        let forged_inner = seal_block(&rogue, 1, &repoint(99, 99));
        store.seed_record(
            &eps[0],
            vault_pointer_name(SECRET, 1).as_str(),
            record_for(1, &forged_inner, 1),
        );

        let fetch = RecordPointerFetch::new(&store);
        let err = block_on(resolve_vault_pointer(
            &fetch,
            SECRET,
            &owner.verifying_key(),
            &ROOT_SCOPE,
            PAYLOAD_VERSION,
        ))
        .expect_err("a forged inner re-point fails the walk closed");
        assert!(
            matches!(err, PointerError::Open(_)),
            "the inner-forge is surfaced verbatim as PointerError::Open, not swallowed"
        );
    }
}
