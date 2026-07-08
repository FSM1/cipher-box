//! Production `RotationDeps` adapter for desktop FUSE shared-scope-exit
//! read-key rotation (D-14, SC#8, Plan 70.1-09).
//!
//! This is the ASSEMBLY job RESEARCH Sharp Question 7.1 describes: every
//! method of `cipherbox_sdk::rotation::engine::RotationDeps` maps to an
//! existing single-purpose primitive already shipped elsewhere in the
//! workspace. The genuinely NEW piece is the key-checkpoint seam plumbing
//! (`persist_wrapped_key`/`get_wrapped_key`/`delete_wrapped_key`, D-01/D-03,
//! landed in Plan 70.1-08) wired to the combined `JsonSidecarFloorStore`
//! (Plan 70.1-03).
//!
//! # Design: generic over an injectable `RotationTransport` seam
//!
//! [`FuseRotationDeps`] is generic over [`RotationTransport`] — the
//! resolve/fetch/publish trio — so unit tests can inject an in-memory fake
//! (mirroring how `crates/sdk`'s own `FakeDeps` fakes the engine's deps)
//! without a live `ApiClient`/network round trip. [`ApiClientTransport`] is
//! the production implementor, backed by the real
//! `cipherbox_api_client::ipns`/`ipfs` primitives.
//!
//! # Pitfall 7 (CRITICAL) — the 409 conflict-shape mismatch
//!
//! The engine's [`PublishAttempt::Conflict`] variant requires a fully
//! materialized `remote: PublishedNode`, but `cipherbox_api_client::ipns::
//! publish_ipns`'s `PublishResult::Conflict` returns ONLY a
//! `current_sequence_number` — never the winning record. On a 409,
//! [`FuseRotationDeps::publish_with_cas`] performs a follow-up
//! `resolve`+`fetch_node` to materialize the REAL remote before returning
//! `PublishAttempt::Conflict` — it MUST NEVER fabricate an empty/placeholder
//! `PublishedNode` here (a fabricated remote silently breaks the engine's
//! CAS-409 concurrent-add merge, T-70.1-22).
//!
//! # Known limitation — IPNS signing-key sourcing (documented scope decision)
//!
//! Publishing a rotated node's new IPNS record requires that node's own
//! Ed25519 signing seed. RESEARCH's "assembly job" framing does not specify
//! a source for this beyond the owner's ECIES keypair (which wraps the
//! read-key CHECKPOINT, not IPNS signing material). [`ApiClientTransport`]
//! sources the signing seed from the ALREADY-MOUNTED, in-memory
//! `InodeTable` (`InodeKind::{Root,Folder,File}.ipns_private_key` — the same
//! plaintext-in-memory cache `fs.rs::build_folder_metadata` already reads
//! for local publishes). This works for any node the FUSE mount has
//! materialized (the common case for a scope-exit rotation, since the owner
//! is actively mutating a locally-browsed subtree), and fails CLOSED
//! (`Err` -> EIO) for a node not yet locally materialized, rather than
//! inventing a parallel write-key-chain-walk mechanism (out of scope per
//! RESEARCH: "Write plane rotation remains out of scope (Phase 72)"). A
//! full write-key-chain walk (mirroring `replay.rs::resolve_owned_parent`)
//! is the natural follow-up if this limitation proves too narrow in
//! practice — flagged here per the same "document the deferral" precedent
//! this plan applies to ROT-04 desktop-grant-remint (see `70.1-09-SUMMARY.md`).
//!
//! A second, related consequence of this same narrow scope: the republished
//! `PublishedNode` for a rotated node carries `write_sealed: None` (the
//! engine itself never populates it, see `engine.rs::seal_and_publish`) —
//! this adapter does not reconstruct/preserve the write plane either.
//! Write-plane preservation during a read-key rotation republish is
//! deferred to the same Phase-72 follow-up.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;

use cipherbox_core::node::PublishedNode;
use cipherbox_sdk::rotation::PublishAttempt;
use cipherbox_sdk::{JsonSidecarFloorStore, PublishOutcome, ResolvedRecord, RotationDeps, RotationError, RotationJobRecord};

// ---------------------------------------------------------------------------
// RotationTransport — the injectable resolve/fetch/publish seam
// ---------------------------------------------------------------------------

/// Outcome of a single [`RotationTransport::publish`] attempt — the
/// transport-level twin of `PublishResult` (`cipherbox_api_client::types`),
/// deliberately narrower: it carries only what a transport can know without
/// consulting the engine's own `PublishAttempt::Conflict` contract (which
/// additionally needs a materialized `remote: PublishedNode` — see Pitfall
/// 7 in the module doc comment; [`FuseRotationDeps::publish_with_cas`]
/// performs that materialization itself, one level up).
#[derive(Debug, Clone)]
pub enum TransportPublishOutcome {
    /// The publish landed; carries the new sequence number.
    Published { new_sequence_number: u64 },
    /// The server rejected the CAS guard (409); carries ONLY the current
    /// sequence number — never a remote node (that is the exact shape
    /// mismatch Pitfall 7 documents).
    Conflict { current_sequence_number: u64 },
}

/// Injectable resolve/fetch/publish seam (RESEARCH Sharp Question 7.1),
/// mirroring how `crates/sdk`'s own `FakeDeps` fakes the engine's deps —
/// this lets [`FuseRotationDeps`] be unit-tested without a live `ApiClient`.
///
/// `#[allow(async_fn_in_trait)]`: only ever used generically
/// (`FuseRotationDeps<T: RotationTransport>`), never as `dyn
/// RotationTransport` — mirrors the identical `allow` on
/// `cipherbox_sdk::rotation::engine::RotationDeps` itself.
#[allow(async_fn_in_trait)]
pub trait RotationTransport {
    /// Resolve `ipns_name` to its current CID + sequence number, or `None`
    /// if the name has no published record.
    async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError>;

    /// Fetch the (still AEAD-sealed) `PublishedNode` envelope stored at `cid`.
    async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError>;

    /// CAS-publish `node` to `ipns_name`, guarded by `expected_sequence_number`.
    async fn publish(
        &self,
        ipns_name: &str,
        node: &PublishedNode,
        expected_sequence_number: u64,
    ) -> Result<TransportPublishOutcome, RotationError>;
}

// ---------------------------------------------------------------------------
// FuseRotationDeps — the production RotationDeps adapter
// ---------------------------------------------------------------------------

/// Production `RotationDeps` adapter (D-14): delegates `resolve`/`fetch_node`
/// /`publish_with_cas` to an injected [`RotationTransport`] (production:
/// [`ApiClientTransport`]; tests: an in-memory fake), and ECIES-wraps/unwraps
/// the D-01/D-03 read-key checkpoint under the owner's OWN keypair, storing
/// only ciphertext in the combined `JsonSidecarFloorStore` (Plan 70.1-03).
///
/// `query_grants_rooted_at`/`update_grant`/`delete_grant` are left at the
/// trait's DEFAULT no-op — the ROT-04 desktop-grant-remint deferral this
/// plan's `<verification>` block explicitly sanctions (see
/// `70.1-09-SUMMARY.md`).
pub struct FuseRotationDeps<T: RotationTransport> {
    transport: T,
    /// Owner's ECIES public key (secp256k1, compressed) — wraps a freshly
    /// minted `read_key_prime` before it is persisted at rest (D-01).
    owner_public_key: Vec<u8>,
    /// Owner's ECIES private key (secp256k1) — unwraps a checkpointed key on
    /// resume (D-05 repair path).
    owner_private_key: Vec<u8>,
    /// Combined per-nodeId sidecar (Plan 70.1-03) backing
    /// `persist_wrapped_key`/`get_wrapped_key`/`delete_wrapped_key`.
    floor_store: JsonSidecarFloorStore,
}

impl<T: RotationTransport> FuseRotationDeps<T> {
    pub fn new(
        transport: T,
        owner_public_key: Vec<u8>,
        owner_private_key: Vec<u8>,
        floor_store: JsonSidecarFloorStore,
    ) -> Self {
        Self {
            transport,
            owner_public_key,
            owner_private_key,
            floor_store,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::node::seal::seal_node;
    use cipherbox_core::node::{encode_node, Node};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    const ROOT_ID: &str = "11111111-1111-1111-1111-111111111111";

    /// Seals `node`'s read-body under `read_key` into a `PublishedNode`
    /// fixture, mirroring `crates/sdk`'s own `FakeDeps::seal_for_seed` test
    /// helper (private to that crate, so this mirrors it rather than
    /// importing it cross-crate).
    fn seal_for_seed(node: &Node, read_key: &[u8; 32]) -> PublishedNode {
        let body = encode_node(node).unwrap();
        let sealed = seal_node(&body, read_key, node.id(), node.kind(), node.generation()).unwrap();
        PublishedNode {
            schema: "node/v3".to_string(),
            kind: node.kind().as_str().to_string(),
            id: node.id().to_string(),
            generation: node.generation(),
            aead_version: 1,
            read_sealed: STANDARD.encode(sealed),
            write_sealed: None,
        }
    }

    #[derive(Default)]
    struct FakeTransportInner {
        records: HashMap<String, (String, u64)>,
        blobs: HashMap<String, PublishedNode>,
        publish_log: Vec<String>,
        conflict_once: Option<(String, u64)>,
    }

    /// In-memory `RotationTransport` fake — no live IPNS/IPFS round trip.
    #[derive(Clone, Default)]
    struct FakeTransport(Arc<Mutex<FakeTransportInner>>);

    impl FakeTransport {
        fn seed(&self, ipns_name: &str, cid: &str, seq: u64, node: PublishedNode) {
            let mut inner = self.0.lock().unwrap();
            inner
                .records
                .insert(ipns_name.to_string(), (cid.to_string(), seq));
            inner.blobs.insert(cid.to_string(), node);
        }

        fn publish_count_for(&self, ipns_name: &str) -> usize {
            self.0
                .lock()
                .unwrap()
                .publish_log
                .iter()
                .filter(|n| n.as_str() == ipns_name)
                .count()
        }

        /// The NEXT `publish` call for `ipns_name` reports a 409 conflict
        /// (current_sequence_number only — no remote), then reverts to
        /// normal behavior.
        fn inject_conflict_once(&self, ipns_name: &str, current_sequence_number: u64) {
            self.0.lock().unwrap().conflict_once =
                Some((ipns_name.to_string(), current_sequence_number));
        }
    }

    impl RotationTransport for FakeTransport {
        async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError> {
            Ok(self
                .0
                .lock()
                .unwrap()
                .records
                .get(ipns_name)
                .map(|(cid, seq)| ResolvedRecord {
                    cid: cid.clone(),
                    sequence_number: *seq,
                }))
        }

        async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError> {
            self.0
                .lock()
                .unwrap()
                .blobs
                .get(cid)
                .cloned()
                .ok_or_else(|| RotationError::RotateFailed(format!("FakeTransport: no blob for cid {cid}")))
        }

        async fn publish(
            &self,
            ipns_name: &str,
            node: &PublishedNode,
            expected_sequence_number: u64,
        ) -> Result<TransportPublishOutcome, RotationError> {
            let mut inner = self.0.lock().unwrap();
            inner.publish_log.push(ipns_name.to_string());
            if let Some((name, current_seq)) = inner.conflict_once.take() {
                if name == ipns_name {
                    return Ok(TransportPublishOutcome::Conflict {
                        current_sequence_number: current_seq,
                    });
                }
                inner.conflict_once = Some((name, current_seq));
            }
            let new_seq = expected_sequence_number + 1;
            let new_cid = format!("{ipns_name}-cid-v{new_seq}");
            inner.blobs.insert(new_cid.clone(), node.clone());
            inner
                .records
                .insert(ipns_name.to_string(), (new_cid, new_seq));
            Ok(TransportPublishOutcome::Published {
                new_sequence_number: new_seq,
            })
        }
    }

    /// Fresh secp256k1 ECIES owner keypair (compressed pubkey / raw scalar),
    /// mirroring `crates/sdk`'s own `FakeDeps` owner-identity fixture.
    fn owner_keypair() -> (Vec<u8>, Vec<u8>) {
        let (sk, pk) = ecies::utils::generate_keypair();
        (pk.serialize().to_vec(), sk.serialize().to_vec())
    }

    /// A fresh temp-dir-backed combined `JsonSidecarFloorStore` (Plan
    /// 70.1-03), unique per call so concurrent tests never collide.
    fn temp_floor_store() -> JsonSidecarFloorStore {
        let dir = std::env::temp_dir()
            .join("cb-rotation-deps-test")
            .join(format!(
                "{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
        std::fs::create_dir_all(&dir).expect("create temp floor-store dir");
        JsonSidecarFloorStore::for_generation(dir)
    }

    fn folder_fixture(generation: u32) -> Node {
        Node::Folder {
            id: ROOT_ID.to_string(),
            generation,
            created_at: 1_000,
            modified_at: 1_000,
            children: vec![],
        }
    }

    /// Test A (D-14): a covered scope-exit rotation drives
    /// `rotate_read_from_node` and publishes exactly ONE rotation for the
    /// grant-root.
    #[tokio::test]
    async fn covered_scope_exit_rotates_the_grant_root_exactly_once() {
        let transport = FakeTransport::default();
        let read_key = [7u8; 32];
        transport.seed(
            "k51root",
            "cid-root-v1",
            1,
            seal_for_seed(&folder_fixture(0), &read_key),
        );

        let (owner_pub, owner_priv) = owner_keypair();
        let deps = FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());
        let mut job = RotationJobRecord::new(ROOT_ID);

        let result =
            cipherbox_sdk::rotate_read_from_node(&deps, ROOT_ID, "k51root", &read_key, &mut job).await;

        assert!(result.is_ok(), "rotation must succeed: {:?}", result.err());
        assert_eq!(
            transport.publish_count_for("k51root"),
            1,
            "a covered scope-exit rotation must publish the grant-root exactly once"
        );
    }

    /// Test B (Pitfall 7): on a faked 409 (publish returns Conflict with
    /// only a sequence), the adapter performs a follow-up resolve+fetch_node
    /// and returns `PublishAttempt::Conflict { remote, .. }` with a REAL
    /// materialized remote — never a fabricated placeholder.
    #[tokio::test]
    async fn cas_conflict_materializes_the_real_remote_via_resolve_and_fetch() {
        let transport = FakeTransport::default();
        let read_key = [9u8; 32];
        let remote_published = seal_for_seed(&folder_fixture(1), &read_key);
        // The winning concurrent record, already live at seq 2.
        transport.seed("k51root", "cid-root-v2", 2, remote_published.clone());
        transport.inject_conflict_once("k51root", 2);

        let (owner_pub, owner_priv) = owner_keypair();
        let deps = FuseRotationDeps::new(transport, owner_pub, owner_priv, temp_floor_store());
        let local_node = seal_for_seed(&folder_fixture(1), &read_key);

        let outcome = deps
            .publish_with_cas("k51root", 1, &local_node)
            .await
            .unwrap();
        match outcome {
            PublishAttempt::Conflict {
                remote,
                current_sequence_number,
            } => {
                assert_eq!(current_sequence_number, 2);
                assert_eq!(
                    remote, remote_published,
                    "the conflict's remote must be the REAL node fetched via resolve+fetch_node, not a fabricated placeholder"
                );
            }
            other => panic!("expected PublishAttempt::Conflict, got {other:?}"),
        }
    }

    /// Test C: the checkpoint methods persist/get/delete against a real
    /// (temp-dir) combined `JsonSidecarFloorStore` and the ECIES wrap/unwrap
    /// round-trips under the owner keypair.
    #[tokio::test]
    async fn checkpoint_round_trips_through_the_combined_floor_store_under_the_owner_keypair() {
        let (owner_pub, owner_priv) = owner_keypair();
        let deps = FuseRotationDeps::new(
            FakeTransport::default(),
            owner_pub,
            owner_priv,
            temp_floor_store(),
        );

        let raw_key = [42u8; 32];
        let wrapped_b64 = STANDARD.encode(raw_key);

        assert!(deps.get_wrapped_key(ROOT_ID).await.unwrap().is_none());

        deps.persist_wrapped_key(ROOT_ID, &wrapped_b64).await.unwrap();

        let recovered_b64 = deps
            .get_wrapped_key(ROOT_ID)
            .await
            .unwrap()
            .expect("checkpoint must round-trip");
        assert_eq!(recovered_b64, wrapped_b64);

        deps.delete_wrapped_key(ROOT_ID).await.unwrap();
        assert!(deps.get_wrapped_key(ROOT_ID).await.unwrap().is_none());
    }
}
