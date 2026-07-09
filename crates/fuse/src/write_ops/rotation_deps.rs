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
use zeroize::Zeroizing;

use cipherbox_api_client::ipns::{resolve_ipns_verified, VerifyError};
use cipherbox_api_client::{ApiClient, ApiError, IpnsPublishRequest, PublishResult};
use cipherbox_core::node::{decode_published_node, encode_published_node, PublishedNode};
use cipherbox_sdk::rotation::PublishAttempt;
use cipherbox_sdk::{
    JsonSidecarFloorStore, PublishOutcome, ResolvedRecord, RotationDeps, RotationError,
    RotationJobRecord,
};

use crate::inode::{InodeKind, InodeTable};

/// TTL for a rotation republish's IPNS record — matches the existing
/// `replay.rs`/first-publish convention (24h) rather than inventing a new
/// value.
const IPNS_RECORD_LIFETIME_MS: u64 = 86_400_000;

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
    /// resume (D-05 repair path). Held in `Zeroizing` so the key bytes are
    /// wiped on drop, consistent with the rest of this file's key handling.
    owner_private_key: Zeroizing<Vec<u8>>,
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
            owner_private_key: Zeroizing::new(owner_private_key),
            floor_store,
        }
    }
}

// impl RotationDeps for FuseRotationDeps<T> — the production adapter (D-14):
// generic over T so the same impl serves both `ApiClientTransport` (real)
// and the test module's `FakeTransport`.
impl<T: RotationTransport> RotationDeps for FuseRotationDeps<T> {
    async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError> {
        self.transport.resolve(ipns_name).await
    }

    async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError> {
        self.transport.fetch_node(cid).await
    }

    /// Pitfall 7 (T-70.1-22): on a 409, performs a follow-up `resolve` +
    /// `fetch_node` to materialize the REAL winning `remote` before
    /// returning `PublishAttempt::Conflict` — never a fabricated
    /// placeholder (a fabricated remote silently breaks the engine's
    /// CAS-409 concurrent-add merge).
    async fn publish_with_cas(
        &self,
        ipns_name: &str,
        expected_sequence_number: u64,
        node: &PublishedNode,
    ) -> Result<PublishAttempt, RotationError> {
        match self
            .transport
            .publish(ipns_name, node, expected_sequence_number)
            .await?
        {
            TransportPublishOutcome::Published {
                new_sequence_number,
            } => Ok(PublishAttempt::Published(PublishOutcome {
                new_sequence_number,
            })),
            TransportPublishOutcome::Conflict {
                current_sequence_number,
            } => {
                let resolved = self.transport.resolve(ipns_name).await?.ok_or_else(|| {
                    RotationError::RotateFailed(format!(
                        "publish_with_cas: 409 conflict for {ipns_name} but a follow-up resolve found nothing"
                    ))
                })?;
                let remote = self.transport.fetch_node(&resolved.cid).await?;
                Ok(PublishAttempt::Conflict {
                    remote,
                    current_sequence_number,
                })
            }
        }
    }

    /// Advisory (D-10) — published IPNS records remain the source of truth.
    /// A durable Rust job checkpoint is not required for correctness
    /// (RESEARCH Sharp Question 7.1); this is a no-op logger.
    async fn persist_job(&self, job: &RotationJobRecord) {
        log::debug!(
            "rotation job checkpoint (advisory, D-10): root_node_id={} completed_nodes={} status={:?}",
            job.root_node_id,
            job.completed_node_ids.len(),
            job.status
        );
    }

    // `query_grants_rooted_at`/`update_grant`/`delete_grant` are left at the
    // trait's DEFAULT no-op — the ROT-04 desktop-grant-remint deferral this
    // plan's <verification> block explicitly sanctions (see
    // 70.1-09-SUMMARY.md "ROT-04 deferral").

    /// D-01/D-03: ECIES-wraps `wrapped_b64`'s raw key material under the
    /// owner's OWN public key before persisting ciphertext-only to the
    /// combined floor store (Plan 70.1-03). Fails closed (D-08) on any
    /// step.
    async fn persist_wrapped_key(
        &self,
        node_id: &str,
        wrapped_b64: &str,
    ) -> Result<(), RotationError> {
        // Decoded plaintext key material: hold it in `Zeroizing` so the buffer
        // is wiped on drop, matching `get_wrapped_key`/`find_ipns_private_key`.
        let raw = Zeroizing::new(STANDARD.decode(wrapped_b64).map_err(|e| {
            RotationError::RotateFailed(format!(
                "persist_wrapped_key: base64 decode failed for {node_id}: {e}"
            ))
        })?);
        let ciphertext = cipherbox_crypto::wrap_key(&raw, &self.owner_public_key).map_err(|e| {
            RotationError::RotateFailed(format!(
                "persist_wrapped_key: wrap_key failed for {node_id}: {e}"
            ))
        })?;
        self.floor_store
            .persist_wrapped_key(node_id, ciphertext)
            .await
    }

    /// Recovers a checkpoint (if any) and ECIES-unwraps it under the
    /// owner's OWN private key, returning the raw key material as base64 —
    /// the engine's `get_wrapped_key` contract per RESEARCH option (b): this
    /// adapter does the ECIES wrap/unwrap itself, keeping the engine
    /// key-material-free.
    async fn get_wrapped_key(&self, node_id: &str) -> Result<Option<String>, RotationError> {
        let Some(ciphertext) = self.floor_store.get_wrapped_key(node_id).await else {
            return Ok(None);
        };
        let raw =
            cipherbox_crypto::unwrap_key(&ciphertext, &self.owner_private_key).map_err(|e| {
                RotationError::RotateFailed(format!(
                    "get_wrapped_key: unwrap_key failed for {node_id}: {e}"
                ))
            })?;
        Ok(Some(STANDARD.encode(raw.as_slice())))
    }

    /// D-04: GC's a checkpoint once it is no longer needed.
    async fn delete_wrapped_key(&self, node_id: &str) -> Result<(), RotationError> {
        self.floor_store.delete_wrapped_key(node_id).await
    }
}

// ---------------------------------------------------------------------------
// ApiClientTransport — production RotationTransport over the real ApiClient
// ---------------------------------------------------------------------------

/// Production [`RotationTransport`] implementor, backed by the real
/// `cipherbox_api_client::ipns`/`ipfs` primitives (RESEARCH Sharp Question
/// 7.1's method->primitive map):
/// - `resolve` -> `resolve_ipns_verified` (the verified/signature-checked
///   fail-closed chokepoint, D-08).
/// - `fetch_node` -> `fetch_content` + `decode_published_node`.
/// - `publish` -> `upload_content` + `create_ipns_record` +
///   `publish_ipns` (request-build precedent: `replay.rs:367/617`).
///
/// `inodes` sources the per-node IPNS signing seed from the ALREADY-MOUNTED
/// `InodeTable` — see the module doc comment's "Known limitation" section
/// for why, and its documented fail-closed behavior when a target node is
/// not locally materialized.
pub struct ApiClientTransport<'a> {
    pub api: &'a ApiClient,
    pub inodes: &'a InodeTable,
}

impl RotationTransport for ApiClientTransport<'_> {
    async fn resolve(&self, ipns_name: &str) -> Result<Option<ResolvedRecord>, RotationError> {
        // sc6-allow: rotation transport's verified fail-closed chokepoint (D-08), not a read-plane bypass.
        match resolve_ipns_verified(self.api, ipns_name).await {
            Ok(v) => Ok(Some(ResolvedRecord {
                cid: v.cid,
                sequence_number: v.sequence_number,
            })),
            Err(VerifyError::Api(ApiError::IpnsNotFound(_))) => Ok(None),
            Err(VerifyError::Api(e)) => Err(RotationError::RotateFailed(format!(
                "resolve: API error for {ipns_name}: {e}"
            ))),
            Err(VerifyError::Invalid(msg)) => Err(RotationError::RotateFailed(format!(
                "resolve: verification failed for {ipns_name}: {msg}"
            ))),
        }
    }

    async fn fetch_node(&self, cid: &str) -> Result<PublishedNode, RotationError> {
        let bytes = cipherbox_api_client::ipfs::fetch_content(self.api, cid)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "fetch_node: fetch_content failed for {cid}: {e}"
                ))
            })?;
        decode_published_node(&bytes).map_err(|e| {
            RotationError::RotateFailed(format!(
                "fetch_node: decode_published_node failed for {cid}: {e}"
            ))
        })
    }

    async fn publish(
        &self,
        ipns_name: &str,
        node: &PublishedNode,
        expected_sequence_number: u64,
    ) -> Result<TransportPublishOutcome, RotationError> {
        // Known limitation (see module doc comment): the signing seed is
        // sourced from the locally-mounted InodeTable — fails CLOSED if
        // this node has not been materialized locally.
        let signing_seed = find_ipns_private_key(self.inodes, ipns_name).ok_or_else(|| {
            RotationError::RotateFailed(format!(
                "publish: no locally-cached IPNS signing key for {ipns_name} \
                 (node not materialized in the local inode table)"
            ))
        })?;
        let seed_arr = to_key32(&signing_seed, "IPNS signing seed")?;

        let node_bytes = encode_published_node(node).map_err(|e| {
            RotationError::RotateFailed(format!(
                "publish: encode_published_node failed for {ipns_name}: {e}"
            ))
        })?;
        let cid = cipherbox_api_client::ipfs::upload_content(self.api, &node_bytes)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "publish: upload_content failed for {ipns_name}: {e}"
                ))
            })?;

        let new_seq = expected_sequence_number.checked_add(1).ok_or_else(|| {
            RotationError::RotateFailed(format!("publish: sequence overflow for {ipns_name}"))
        })?;
        let value = format!("/ipfs/{cid}");
        let record =
            cipherbox_core::create_ipns_record(&seed_arr, &value, new_seq, IPNS_RECORD_LIFETIME_MS)
                .map_err(|e| {
                    RotationError::RotateFailed(format!(
                        "publish: create_ipns_record failed for {ipns_name}: {e}"
                    ))
                })?;
        let marshaled = cipherbox_core::marshal_ipns_record(&record).map_err(|e| {
            RotationError::RotateFailed(format!(
                "publish: marshal_ipns_record failed for {ipns_name}: {e}"
            ))
        })?;
        let record_b64 = STANDARD.encode(&marshaled);

        let req = IpnsPublishRequest {
            ipns_name: ipns_name.to_string(),
            record: record_b64,
            metadata_cid: cid,
            encrypted_ipns_private_key: None,
            key_epoch: None,
            expected_sequence_number: Some(expected_sequence_number.to_string()),
        };
        match cipherbox_api_client::ipns::publish_ipns(self.api, &req)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "publish: publish_ipns failed for {ipns_name}: {e}"
                ))
            })? {
            PublishResult::Success => Ok(TransportPublishOutcome::Published {
                new_sequence_number: new_seq,
            }),
            PublishResult::Conflict {
                current_sequence_number,
            } => {
                let parsed = current_sequence_number.parse::<u64>().map_err(|e| {
                    RotationError::RotateFailed(format!(
                        "publish: failed to parse conflicting sequence number for {ipns_name}: {e}"
                    ))
                })?;
                Ok(TransportPublishOutcome::Conflict {
                    current_sequence_number: parsed,
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Local InodeTable lookups (signing-key sourcing + grant-root state)
// ---------------------------------------------------------------------------

/// Copies a slice into a fixed 32-byte array, failing closed (rather than
/// panicking) on the wrong length.
fn to_key32(bytes: &[u8], what: &str) -> Result<[u8; 32], RotationError> {
    bytes.try_into().map_err(|_| {
        RotationError::RotateFailed(format!(
            "{what} has wrong length (got {}, expected 32)",
            bytes.len()
        ))
    })
}

/// Scans the locally-mounted `InodeTable` for a node whose OWN `ipns_name`
/// matches, returning its cached (plaintext, in-memory) IPNS signing seed —
/// see the module doc comment's "Known limitation" section.
fn find_ipns_private_key(inodes: &InodeTable, ipns_name: &str) -> Option<Zeroizing<Vec<u8>>> {
    inodes.inodes.values().find_map(|inode| {
        let (candidate_name, key) = match &inode.kind {
            InodeKind::Root {
                ipns_name,
                ipns_private_key,
                ..
            } => (ipns_name, ipns_private_key),
            InodeKind::Folder {
                ipns_name,
                ipns_private_key,
                ..
            } => (ipns_name, ipns_private_key),
            InodeKind::File {
                ipns_name,
                ipns_private_key,
                ..
            } => (ipns_name, ipns_private_key),
        };
        (candidate_name == ipns_name && !key.is_empty()).then(|| Zeroizing::new(key.to_vec()))
    })
}

/// Scans the locally-mounted `InodeTable` for the grant-root inode matching
/// `ipns_name`, returning its stable `node_id` + current `read_key` — the
/// two inputs `rotate_read_on_scope_exit`'s stub lacked (RESEARCH Sharp
/// Question 7.2).
pub(crate) fn find_grant_root_state(
    inodes: &InodeTable,
    ipns_name: &str,
) -> Option<(String, Zeroizing<[u8; 32]>)> {
    inodes.inodes.values().find_map(|inode| match &inode.kind {
        InodeKind::Root {
            ipns_name: n,
            read_key,
            ..
        } if n == ipns_name => Some((inode.node_id.clone(), Zeroizing::new(**read_key))),
        InodeKind::Folder {
            ipns_name: n,
            read_key,
            ..
        } if n == ipns_name => Some((inode.node_id.clone(), Zeroizing::new(**read_key))),
        _ => None,
    })
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
                .ok_or_else(|| {
                    RotationError::RotateFailed(format!("FakeTransport: no blob for cid {cid}"))
                })
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
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());
        let mut job = RotationJobRecord::new(ROOT_ID);

        let result =
            cipherbox_sdk::rotate_read_from_node(&deps, ROOT_ID, "k51root", &read_key, &mut job)
                .await;

        assert!(result.is_ok(), "rotation must succeed: {:?}", result.err());
        assert_eq!(
            transport.publish_count_for("k51root"),
            1,
            "a covered scope-exit rotation must publish the grant-root exactly once"
        );
    }

    /// DIAGNOSIS PROOF (scope-exit-part-a-fail, Defect 1 / the "+2" bump): the
    /// grant-root that the D-16 desktop-e2e rotates STILL HAS A CHILD at
    /// rotation time (the delete removes it AFTER the scope-exit gate runs).
    /// A grant-root WITH a child is published TWICE by the rotation walk —
    /// `rotate_one(root)` (engine.rs:1418) publishes the root once, then the
    /// batched `republish_parent(root)` (engine.rs:2115) publishes it AGAIN
    /// after the child rotates and is re-sealed into the parent's child
    /// mirror. Both publishes are under the parent's NEW read key. This is why
    /// the e2e sees a `+2` IPNS sequence bump on the grant-root even though it
    /// asserts `+1` ("exactly one rotation publish"): that expectation is only
    /// correct for a CHILDLESS scope root (the test above), not for a
    /// scope-root that has a child at rotation time. This is deterministic and
    /// independent of the desktop delete-relink republish.
    #[tokio::test]
    async fn covered_scope_exit_with_a_child_publishes_the_grant_root_twice() {
        use cipherbox_core::node::{Node, NodeKind, SealedChildRef};

        const CHILD_ID: &str = "22222222-2222-2222-2222-222222222222";
        let child_ipns = "k51child";

        let transport = FakeTransport::default();
        let root_read_key = [7u8; 32];
        let root_write_key = [8u8; 32];
        let child_read_key = [9u8; 32];
        let child_write_key = [10u8; 32];

        // The grant-root's child ref, sealed under the ROOT's keys (generation
        // 0) exactly as `build_folder_metadata` would have produced it.
        let (child_ref, _wref): (SealedChildRef, _) = cipherbox_sdk::build_child_refs(
            &child_read_key,
            &child_write_key,
            &root_read_key,
            &root_write_key,
            CHILD_ID,
            child_ipns,
            "secret-sub",
            NodeKind::Folder,
            0,
            0,
        )
        .expect("build_child_refs");

        // Seed the child (an empty folder) sealed under its OWN read key.
        let child_node = Node::Folder {
            id: CHILD_ID.to_string(),
            generation: 0,
            created_at: 1_000,
            modified_at: 1_000,
            children: vec![],
        };
        transport.seed(
            child_ipns,
            "cid-child-v1",
            1,
            seal_for_seed(&child_node, &child_read_key),
        );

        // Seed the grant-root folder holding that one child, sealed under the
        // root read key.
        let root_node = Node::Folder {
            id: ROOT_ID.to_string(),
            generation: 0,
            created_at: 1_000,
            modified_at: 1_000,
            children: vec![child_ref],
        };
        transport.seed(
            "k51root",
            "cid-root-v1",
            1,
            seal_for_seed(&root_node, &root_read_key),
        );

        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());
        let mut job = RotationJobRecord::new(ROOT_ID);

        let result = cipherbox_sdk::rotate_read_from_node(
            &deps,
            ROOT_ID,
            "k51root",
            &root_read_key,
            &mut job,
        )
        .await;

        assert!(result.is_ok(), "rotation must succeed: {:?}", result.err());
        assert_eq!(
            transport.publish_count_for("k51root"),
            2,
            "REGRESSION PROOF: a grant-root that still has a child at rotation time is published \
             TWICE (rotate_one + batched republish_parent), so the desktop-e2e '+1 exactly one \
             rotation publish' assertion is violated (observed +2). Contrast the childless case \
             above, which publishes exactly once."
        );
        // The child rotates exactly once (its own ipns), confirming the second
        // grant-root publish is the batched parent re-mirror, not a child leak.
        assert_eq!(
            transport.publish_count_for(child_ipns),
            1,
            "the child rotates exactly once on its own ipns"
        );
    }

    /// 70.1-13a COALESCED FIX (through the production `FuseRotationDeps`
    /// adapter): a covered scope-exit delete of the grant-root's ONLY child
    /// passes an EMPTY `root_children` override, so the rotation publishes the
    /// grant-root EXACTLY ONCE (empty, under the new key) and never rotates the
    /// deleted child. This is the coalesced replacement for the `..._twice`
    /// case above (rotate_one + republish_parent) PLUS the suppressed stale-key
    /// relink — the single, revocation-correct publish the D-16 leg now asserts.
    #[tokio::test]
    async fn covered_scope_exit_with_empty_override_publishes_the_grant_root_once() {
        use cipherbox_core::node::{Node, NodeKind, SealedChildRef};

        const CHILD_ID: &str = "22222222-2222-2222-2222-222222222222";
        let child_ipns = "k51child";

        let transport = FakeTransport::default();
        let root_read_key = [7u8; 32];
        let root_write_key = [8u8; 32];
        let child_read_key = [9u8; 32];
        let child_write_key = [10u8; 32];

        let (child_ref, _wref): (SealedChildRef, _) = cipherbox_sdk::build_child_refs(
            &child_read_key,
            &child_write_key,
            &root_read_key,
            &root_write_key,
            CHILD_ID,
            child_ipns,
            "secret-sub",
            NodeKind::Folder,
            0,
            0,
        )
        .expect("build_child_refs");

        let child_node = Node::Folder {
            id: CHILD_ID.to_string(),
            generation: 0,
            created_at: 1_000,
            modified_at: 1_000,
            children: vec![],
        };
        transport.seed(
            child_ipns,
            "cid-child-v1",
            1,
            seal_for_seed(&child_node, &child_read_key),
        );
        // The grant-root still HAS the child in its published record at rotation
        // time (the delete removes it only after the gate).
        let root_node = Node::Folder {
            id: ROOT_ID.to_string(),
            generation: 0,
            created_at: 1_000,
            modified_at: 1_000,
            children: vec![child_ref],
        };
        transport.seed(
            "k51root",
            "cid-root-v1",
            1,
            seal_for_seed(&root_node, &root_read_key),
        );

        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());
        let mut job = RotationJobRecord::new(ROOT_ID);

        // The coalesced covered-delete path: empty post-delete child list.
        let result = cipherbox_sdk::rotate_read_from_node_with_root_children(
            &deps,
            ROOT_ID,
            "k51root",
            &root_read_key,
            &mut job,
            Vec::new(),
        )
        .await;

        assert!(result.is_ok(), "rotation must succeed: {:?}", result.err());
        assert_eq!(
            transport.publish_count_for("k51root"),
            1,
            "COALESCED: the covered scope-exit publishes the grant-root exactly ONCE \
             (post-delete, new key) — no batched republish_parent, no stale-key relink"
        );
        assert_eq!(
            transport.publish_count_for(child_ipns),
            0,
            "the deleted child is excluded from the override, so it is never rotated"
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

        deps.persist_wrapped_key(ROOT_ID, &wrapped_b64)
            .await
            .unwrap();

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
