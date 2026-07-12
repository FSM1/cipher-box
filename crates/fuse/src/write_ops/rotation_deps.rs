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
use cipherbox_api_client::shares::SentShareResponse;
use cipherbox_api_client::{ApiClient, ApiError, IpnsPublishRequest, PublishResult};
use cipherbox_core::node::seal::{seal_child_write_key, seal_node};
use cipherbox_core::node::{
    decode_published_node, encode_published_node, encode_write_body, NodeKind, NodeWriteBody,
    PublishedNode, WriteChildRef,
};
use cipherbox_sdk::rotation::{GrantRow, PublishAttempt};
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

    /// Fetch every sent-share row for the authenticated owner (the raw wire
    /// rows, unfiltered) — the source `FuseRotationDeps::query_grants_rooted_at`
    /// client-side-filters by `root_node_id` (Todo 2, mirrors
    /// `owner-reconcile.ts::buildGrantRemintCallbacks`'s `queryGrantsFn`).
    async fn collect_sent_shares(&self) -> Result<Vec<SentShareResponse>, RotationError>;

    /// Re-mint a retained recipient's ALREADY-ECIES-wrapped read key at
    /// `new_generation` — `PATCH /shares/:shareId/grant`. `new_generation`'s
    /// type mirrors `RotationDeps::update_grant`'s own generation param
    /// (`u32`) so `FuseRotationDeps::update_grant` can forward without
    /// converting.
    async fn update_grant(
        &self,
        share_id: &str,
        encrypted_read_key: &str,
        new_generation: u32,
    ) -> Result<(), RotationError>;

    /// Hard-revoke a single share/invite grant by ID — `DELETE /shares/:shareId`.
    async fn revoke_share(&self, share_id: &str) -> Result<(), RotationError>;
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
/// `query_grants_rooted_at`/`update_grant`/`delete_grant` (Plan 74-05, T-74-07)
/// delegate to the same injected [`RotationTransport`] seam via
/// `collect_sent_shares`/`update_grant`/`revoke_share`, closing the ROT-04
/// desktop-grant-remint deferral `70.1-09-SUMMARY.md` documented.
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

    /// T-74-07 (Todo 2): re-mints retained sharees instead of the ROT-04
    /// no-op default de-authorizing every recipient. Client-side-filters
    /// `self.transport.collect_sent_shares()` by `root_node_id == node_id`
    /// (mirrors `owner-reconcile.ts::buildGrantRemintCallbacks`'s
    /// `queryGrantsFn`) and hex-decodes each `recipient_public_key` (0x
    /// stripped, 04 prefix kept — T-74-08). `is_revoked` is always `false`
    /// from this source: revoked shares are hard-deleted server-side, so
    /// they never appear in this query result (Pitfall 2 / T-74-14 — a
    /// revoked recipient is cut by ABSENCE, not a flag).
    async fn query_grants_rooted_at(&self, node_id: &str) -> Result<Vec<GrantRow>, RotationError> {
        let shares = self.transport.collect_sent_shares().await?;
        shares
            .into_iter()
            .filter(|s| s.root_node_id == node_id)
            .map(|s| {
                let recipient_public_key = cipherbox_crypto::utils::hex_to_bytes(
                    s.recipient_public_key.trim_start_matches("0x"),
                )
                .map_err(|e| {
                    RotationError::RotateFailed(format!(
                        "query_grants_rooted_at: bad recipient_public_key for {}: {e}",
                        s.share_id
                    ))
                })?;
                Ok(GrantRow {
                    share_id: s.share_id,
                    recipient_public_key,
                    is_revoked: false,
                })
            })
            .collect()
    }

    /// T-74-07 (Todo 2): forwards the ALREADY-ECIES-wrapped read key through
    /// the transport seam — no re-wrapping here (the caller,
    /// `re_mint_grants_rooted_at`, performs `cipherbox_crypto::wrap_key`
    /// itself before invoking this method).
    async fn update_grant(
        &self,
        share_id: &str,
        encrypted_read_key: &str,
        new_generation: u32,
    ) -> Result<(), RotationError> {
        self.transport
            .update_grant(share_id, encrypted_read_key, new_generation)
            .await
    }

    /// T-74-07 (Todo 2): forwards through the transport seam's
    /// `revoke_share`. Reachable only in principle (Pitfall 2: this source's
    /// `is_revoked` is always `false`, so the engine never actually calls
    /// this for a grant returned by `query_grants_rooted_at` above) — kept
    /// for engine-contract completeness.
    async fn delete_grant(&self, share_id: &str) -> Result<(), RotationError> {
        self.transport.revoke_share(share_id).await
    }

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

        // D-01: the read-key rotation engine hands us a node with
        // `write_sealed: None`. Reconstruct + inject the write-body from the
        // locally-materialized InodeTable, re-sealed under the node's OWN write
        // key at its NEW generation (ROLE_BODY 0x01) — restoring owned-walkability
        // and `replay.rs` signing-seed durability. Fail-open to the unchanged
        // (None) node for a non-materialized node (D-01b). Never rotates/mutates
        // the write plane — the child write keys are copied verbatim.
        let reconstructed_node;
        let node = if node.write_sealed.is_none() {
            match reconstruct_write_body(self.inodes, ipns_name, node.generation) {
                Some(sealed) => {
                    let mut cloned = node.clone();
                    cloned.write_sealed = Some(STANDARD.encode(sealed));
                    reconstructed_node = cloned;
                    &reconstructed_node
                }
                None => node,
            }
        } else {
            node
        };

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

    async fn collect_sent_shares(&self) -> Result<Vec<SentShareResponse>, RotationError> {
        cipherbox_api_client::shares::collect_sent_shares(self.api)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "collect_sent_shares: GET /shares/sent failed: {e}"
                ))
            })
    }

    async fn update_grant(
        &self,
        share_id: &str,
        encrypted_read_key: &str,
        new_generation: u32,
    ) -> Result<(), RotationError> {
        cipherbox_api_client::shares::update_grant(
            self.api,
            share_id,
            encrypted_read_key,
            u64::from(new_generation),
        )
        .await
        .map_err(|e| {
            RotationError::RotateFailed(format!("update_grant: PATCH failed for {share_id}: {e}"))
        })
    }

    async fn revoke_share(&self, share_id: &str) -> Result<(), RotationError> {
        cipherbox_api_client::shares::revoke_share(self.api, share_id)
            .await
            .map_err(|e| {
                RotationError::RotateFailed(format!(
                    "revoke_share: DELETE failed for {share_id}: {e}"
                ))
            })
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

/// Reconstruct a node's write-body from the locally-mounted `InodeTable` and
/// re-seal it under the node's OWN write key at `new_generation` (ROLE_BODY
/// 0x01 AAD), returning the sealed write-body bytes.
///
/// D-01: a scope-exit read-key rotation republish otherwise emits
/// `write_sealed: None` (the read-key rotation engine never populates it, and
/// this FUSE adapter — a Phase-72 deferral — never reconstructed it). That
/// floods `list_folder_owned` with "owned child has no write_sealed body" AND
/// is a durability hole (`replay.rs::recover_signing_seed` cannot recover the
/// node's signing seed after rotation+remount). This rebuilds the write plane
/// from the in-memory `InodeTable` (the node's own stable write key +
/// `ipns_private_key` + child `WriteChildRef`s rebuilt from child inodes' write
/// keys — all read-key-rotation-independent) and re-seals via `seal_node` at
/// the node's NEW generation.
///
/// Fail-open to `None` (D-01b, mirroring `find_ipns_private_key`) when the node
/// is NOT locally materialized. NEVER rotates or mutates the write plane — the
/// child write keys are copied verbatim from the child inodes.
///
/// Child `WriteChildRef.write_key_sealed` is sealed under THIS node's write key
/// at AAD generation `0` — the `build_folder_metadata` / `build_child_refs`
/// write-splice convention (the child write plane is not rotated here; only the
/// node's OWN write-body ROLE_BODY seal uses `new_generation`). Recipient-pin
/// preservation is a D-03b concern added in 80-05 once the field is populated on
/// the inode — this reconstruction handles keys + children only, emitting an
/// empty pin list.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) fn reconstruct_write_body(
    inodes: &InodeTable,
    ipns_name: &str,
    new_generation: u32,
) -> Option<Vec<u8>> {
    use zeroize::Zeroize as _;

    // Locate the node by its OWN ipns_name (mirrors `find_ipns_private_key`),
    // pulling its stable node_id, kind, write key, signing seed, and child inos.
    let (node_id, node_kind, node_write_key, ipns_private_key, child_inos) =
        inodes.inodes.values().find_map(|inode| {
            let (candidate_name, kind, write_key, ipns_priv) = match &inode.kind {
                InodeKind::Root {
                    ipns_name,
                    write_key,
                    ipns_private_key,
                    ..
                } => (ipns_name, NodeKind::Root, write_key, ipns_private_key),
                InodeKind::Folder {
                    ipns_name,
                    write_key,
                    ipns_private_key,
                    ..
                } => (ipns_name, NodeKind::Folder, write_key, ipns_private_key),
                InodeKind::File {
                    ipns_name,
                    write_key,
                    ipns_private_key,
                    ..
                } => (ipns_name, NodeKind::File, write_key, ipns_private_key),
            };
            (candidate_name == ipns_name && !ipns_priv.is_empty()).then(|| {
                (
                    inode.node_id.clone(),
                    kind,
                    Zeroizing::new(**write_key),
                    Zeroizing::new(ipns_priv.to_vec()),
                    inode.children.clone().unwrap_or_default(),
                )
            })
        })?;

    // Rebuild the child write-chain from each child inode's OWN write key —
    // read-key-rotation-independent, copied verbatim (never re-derived/rotated).
    // Children with no IPNS identity yet (freshly created, never published) are
    // skipped, mirroring `build_folder_metadata`.
    let mut write_children: Vec<WriteChildRef> = Vec::new();
    for child_ino in child_inos {
        let Some(child) = inodes.inodes.get(&child_ino) else {
            continue;
        };
        let (child_kind, child_ipns, child_write_key) = match &child.kind {
            InodeKind::Folder {
                ipns_name,
                write_key,
                ..
            } => (NodeKind::Folder, ipns_name, Zeroizing::new(**write_key)),
            InodeKind::File {
                ipns_name,
                write_key,
                ..
            } => (NodeKind::File, ipns_name, Zeroizing::new(**write_key)),
            InodeKind::Root { .. } => continue,
        };
        if child_ipns.is_empty() {
            continue;
        }
        let sealed = seal_child_write_key(
            &child_write_key,
            &node_write_key,
            &child.node_id,
            child_kind,
            0,
        )
        .ok()?;
        write_children.push(WriteChildRef {
            child_id: child.node_id.clone(),
            write_key_sealed: STANDARD.encode(sealed),
        });
    }

    // Assemble + seal the write-body under the node's OWN write key at the NEW
    // generation (ROLE_BODY 0x01) — the exact AAD `recover_signing_seed` rebuilds.
    let mut write_body = NodeWriteBody {
        ipns_private_key: ipns_private_key.to_vec(),
        write_children,
        recipient_pins: Vec::new(),
    };
    let wb_bytes = encode_write_body(&write_body).ok()?;
    // Scrub the bare signing-seed copy inside the (non-Zeroizing) write body once
    // it has been encoded (crypto rule #6; mirrors `build_folder_metadata`).
    write_body.ipns_private_key.zeroize();

    seal_node(&wb_bytes, &node_write_key, &node_id, node_kind, new_generation).ok()
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
        /// In-memory `GET /shares/sent` fixture rows (Task 1: grant-seam
        /// tests), consumed verbatim by `collect_sent_shares`.
        sent_shares: Vec<SentShareResponse>,
        /// D-02 call-counter: how many times `collect_sent_shares` has been
        /// invoked. A job-scoped cache bounds this to `<= 1` per rotation walk,
        /// regardless of the number of rotated nodes (mirrors the
        /// `publish_log`/`publish_count_for` pattern).
        collect_sent_shares_calls: usize,
        /// Ordered log of every `update_grant` call:
        /// `(share_id, encrypted_read_key, new_generation)`.
        updated_grants: Vec<(String, String, u32)>,
        /// Ordered log of every `revoke_share` call's `share_id`.
        revoked_shares: Vec<String>,
        /// If set, the NEXT `update_grant` call returns this error message
        /// wrapped in `RotationError::RotateFailed`, then clears.
        fail_next_update_grant: Option<String>,
        /// If set, the NEXT `revoke_share` call returns this error message
        /// wrapped in `RotationError::RotateFailed`, then clears.
        fail_next_revoke_share: Option<String>,
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

        /// Seeds the in-memory `GET /shares/sent` fixture rows returned by
        /// the next `collect_sent_shares` call.
        fn seed_sent_shares(&self, shares: Vec<SentShareResponse>) {
            self.0.lock().unwrap().sent_shares = shares;
        }

        /// How many times `collect_sent_shares` has been called so far (D-02
        /// call-count assertion — a job-scoped cache must keep this `<= 1`).
        fn collect_sent_shares_count(&self) -> usize {
            self.0.lock().unwrap().collect_sent_shares_calls
        }

        /// Every `update_grant` call captured so far, in order.
        fn updated_grants(&self) -> Vec<(String, String, u32)> {
            self.0.lock().unwrap().updated_grants.clone()
        }

        /// Every `revoke_share` call's `share_id`, in order.
        fn revoked_shares(&self) -> Vec<String> {
            self.0.lock().unwrap().revoked_shares.clone()
        }

        /// The NEXT `update_grant` call fails with `RotationError::RotateFailed(message)`.
        fn fail_next_update_grant(&self, message: &str) {
            self.0.lock().unwrap().fail_next_update_grant = Some(message.to_string());
        }

        /// The NEXT `revoke_share` call fails with `RotationError::RotateFailed(message)`.
        fn fail_next_revoke_share(&self, message: &str) {
            self.0.lock().unwrap().fail_next_revoke_share = Some(message.to_string());
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

        async fn collect_sent_shares(&self) -> Result<Vec<SentShareResponse>, RotationError> {
            let mut inner = self.0.lock().unwrap();
            inner.collect_sent_shares_calls += 1;
            Ok(inner.sent_shares.clone())
        }

        async fn update_grant(
            &self,
            share_id: &str,
            encrypted_read_key: &str,
            new_generation: u32,
        ) -> Result<(), RotationError> {
            let mut inner = self.0.lock().unwrap();
            if let Some(message) = inner.fail_next_update_grant.take() {
                return Err(RotationError::RotateFailed(message));
            }
            inner.updated_grants.push((
                share_id.to_string(),
                encrypted_read_key.to_string(),
                new_generation,
            ));
            Ok(())
        }

        async fn revoke_share(&self, share_id: &str) -> Result<(), RotationError> {
            let mut inner = self.0.lock().unwrap();
            if let Some(message) = inner.fail_next_revoke_share.take() {
                return Err(RotationError::RotateFailed(message));
            }
            inner.revoked_shares.push(share_id.to_string());
            Ok(())
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

    /// A `GET /shares/sent` row fixture for the Test D grant-seam suite —
    /// only the fields these tests actually exercise vary per call.
    fn sent_share_fixture(
        share_id: &str,
        root_node_id: &str,
        recipient_public_key_hex: &str,
    ) -> SentShareResponse {
        SentShareResponse {
            share_id: share_id.to_string(),
            recipient_public_key: recipient_public_key_hex.to_string(),
            encrypted_read_key: "deadbeef".to_string(),
            encrypted_write_key: None,
            root_node_id: root_node_id.to_string(),
            share_root_ipns_name: "k51root".to_string(),
            root_generation: "1".to_string(),
            item_name_encrypted: None,
            created_at: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    /// Test D (Todo 2, T-74-07): `query_grants_rooted_at` client-side
    /// filters `collect_sent_shares`'s rows by `root_node_id == node_id`,
    /// hex-decodes `recipient_public_key` (0x stripped, 04 prefix kept), and
    /// always reports `is_revoked: false` from this source (Pitfall 2 — a
    /// revoked recipient's row never appears here at all).
    #[tokio::test]
    async fn query_grants_rooted_at_filters_by_root_node_id_and_hex_decodes_recipient_key() {
        const OTHER_NODE_ID: &str = "33333333-3333-3333-3333-333333333333";
        let transport = FakeTransport::default();
        transport.seed_sent_shares(vec![
            sent_share_fixture(
                "share-in-scope",
                ROOT_ID,
                "0x04aabbccdd00112233445566778899aabbccddeeff001122334455667788990011",
            ),
            sent_share_fixture("share-other-root", OTHER_NODE_ID, "0x04ff"),
        ]);

        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());

        let rows = deps
            .query_grants_rooted_at(ROOT_ID)
            .await
            .expect("query_grants_rooted_at must succeed");

        assert_eq!(
            rows.len(),
            1,
            "only the row whose root_node_id matches the queried node_id is returned"
        );
        let row = &rows[0];
        assert_eq!(row.share_id, "share-in-scope");
        assert!(
            row.recipient_public_key.starts_with(&[0x04]),
            "recipient_public_key must be hex-decoded raw bytes starting with the 0x04 uncompressed-key prefix, got {:?}",
            row.recipient_public_key
        );
        assert_eq!(
            row.recipient_public_key.len(),
            33,
            "the decoded fixture key is 33 bytes (04 prefix + 32-byte body)"
        );
        assert!(
            !row.is_revoked,
            "is_revoked is always false from this source (revoked shares are hard-deleted server-side)"
        );
    }

    /// Test D: `update_grant` forwards `share_id`/`encrypted_read_key`/
    /// `new_generation` verbatim through the `RotationTransport` seam —
    /// no re-wrapping (the caller already ECIES-wrapped the key).
    #[tokio::test]
    async fn update_grant_forwards_through_the_transport_seam() {
        let transport = FakeTransport::default();
        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());

        deps.update_grant("share-1", "already-wrapped-hex-ciphertext", 5)
            .await
            .expect("update_grant must succeed");

        assert_eq!(
            transport.updated_grants(),
            vec![(
                "share-1".to_string(),
                "already-wrapped-hex-ciphertext".to_string(),
                5
            )]
        );
    }

    /// Test D: a transport-level `update_grant` failure maps to
    /// `RotationError::RotateFailed`.
    #[tokio::test]
    async fn update_grant_transport_error_maps_to_rotate_failed() {
        let transport = FakeTransport::default();
        transport.fail_next_update_grant("PATCH /shares/share-1/grant failed: 500");
        let (owner_pub, owner_priv) = owner_keypair();
        let deps = FuseRotationDeps::new(transport, owner_pub, owner_priv, temp_floor_store());

        let err = deps
            .update_grant("share-1", "ciphertext", 5)
            .await
            .expect_err("a transport failure must surface as an error");
        assert!(matches!(err, RotationError::RotateFailed(_)));
    }

    /// Test D: `delete_grant` forwards `share_id` through the transport
    /// seam's `revoke_share`.
    #[tokio::test]
    async fn delete_grant_forwards_through_the_transport_seam() {
        let transport = FakeTransport::default();
        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());

        deps.delete_grant("share-revoked")
            .await
            .expect("delete_grant must succeed");

        assert_eq!(
            transport.revoked_shares(),
            vec!["share-revoked".to_string()]
        );
    }

    /// Test D: a transport-level `revoke_share` failure maps to
    /// `RotationError::RotateFailed`.
    #[tokio::test]
    async fn delete_grant_transport_error_maps_to_rotate_failed() {
        let transport = FakeTransport::default();
        transport.fail_next_revoke_share("DELETE /shares/share-1 failed: 404");
        let (owner_pub, owner_priv) = owner_keypair();
        let deps = FuseRotationDeps::new(transport, owner_pub, owner_priv, temp_floor_store());

        let err = deps
            .delete_grant("share-1")
            .await
            .expect_err("a transport failure must surface as an error");
        assert!(matches!(err, RotationError::RotateFailed(_)));
    }

    // -----------------------------------------------------------------------
    // D-01 reconstruction + D-02 sent-shares cache (Plan 80-02)
    // -----------------------------------------------------------------------

    const RECON_FOLDER_NODE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
    const RECON_CHILD_NODE_ID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";

    /// Minimal directory `FileAttrs` for a test inode.
    fn recon_dir_attrs(ino: u64) -> crate::inode::FileAttrs {
        let now = std::time::SystemTime::now();
        crate::inode::FileAttrs {
            ino,
            size: 0,
            blocks: 0,
            atime: now,
            mtime: now,
            ctime: now,
            crtime: now,
            is_dir: true,
            perm: 0o755,
            nlink: 2,
        }
    }

    /// Build an `InodeTable` with a materialized Folder node (own write_key +
    /// ipns_private_key) holding one materialized child folder (own write_key).
    /// Returns `(table, folder_ipns, folder_write_key, folder_ipns_private_key,
    /// child_write_key)`.
    fn table_with_materialized_folder() -> (InodeTable, String, [u8; 32], Vec<u8>, [u8; 32]) {
        use crate::inode::{InodeData, ROOT_INO};

        let mut table = InodeTable::new();
        let folder_ino = table.allocate_ino();
        let child_ino = table.allocate_ino();

        let folder_write_key = [21u8; 32];
        let folder_ipns_private_key = vec![31u8; 32];
        let child_write_key = [22u8; 32];

        table.insert(InodeData {
            ino: folder_ino,
            node_id: RECON_FOLDER_NODE_ID.to_string(),
            parent_ino: ROOT_INO,
            name: "folder".to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51recon-folder".to_string(),
                read_key: Zeroizing::new([11u8; 32]),
                write_key: Zeroizing::new(folder_write_key),
                ipns_private_key: Zeroizing::new(folder_ipns_private_key.clone()),
                children_loaded: true,
            },
            attr: recon_dir_attrs(folder_ino),
            children: Some(vec![child_ino]),
            write_generation: 0,
        });
        table.insert(InodeData {
            ino: child_ino,
            node_id: RECON_CHILD_NODE_ID.to_string(),
            parent_ino: folder_ino,
            name: "child".to_string(),
            kind: InodeKind::Folder {
                ipns_name: "k51recon-child".to_string(),
                read_key: Zeroizing::new([12u8; 32]),
                write_key: Zeroizing::new(child_write_key),
                ipns_private_key: Zeroizing::new(vec![32u8; 32]),
                children_loaded: true,
            },
            attr: recon_dir_attrs(child_ino),
            children: Some(vec![]),
            write_generation: 0,
        });

        (
            table,
            "k51recon-folder".to_string(),
            folder_write_key,
            folder_ipns_private_key,
            child_write_key,
        )
    }

    /// Test A (D-01): `reconstruct_write_body` for a materialized folder returns
    /// a write-body that `unseal_node` (under the node's OWN write key, at the
    /// NEW generation, ROLE_BODY 0x01) decodes back to a `NodeWriteBody` whose
    /// `ipns_private_key` and child `WriteChildRef`(s) match the InodeTable
    /// inputs — and whose child write key is copied verbatim (no rotation).
    #[test]
    fn reconstruct_write_body_round_trips_ipns_key_and_child_write_refs() {
        use cipherbox_core::node::seal::{unseal_child_write_key, unseal_node};
        use cipherbox_core::node::{decode_write_body, NodeKind};

        let (table, folder_ipns, folder_write_key, folder_ipns_private_key, child_write_key) =
            table_with_materialized_folder();
        let new_generation = 7u32;

        let sealed = reconstruct_write_body(&table, &folder_ipns, new_generation)
            .expect("a materialized node reconstructs Some");

        let wb_bytes = unseal_node(
            &sealed,
            &folder_write_key,
            RECON_FOLDER_NODE_ID,
            NodeKind::Folder,
            new_generation,
        )
        .expect("unseal the reconstructed write-body under the node write key at the new generation");
        let wb = decode_write_body(&wb_bytes).expect("decode the reconstructed write-body");

        assert_eq!(
            wb.ipns_private_key, folder_ipns_private_key,
            "the reconstructed write-body carries the node's own signing seed"
        );
        assert_eq!(
            wb.write_children.len(),
            1,
            "one materialized child -> exactly one WriteChildRef"
        );
        let wcr = &wb.write_children[0];
        assert_eq!(
            wcr.child_id, RECON_CHILD_NODE_ID,
            "the WriteChildRef is keyed by the child's stable node_id"
        );

        let sealed_child = STANDARD
            .decode(&wcr.write_key_sealed)
            .expect("child write_key_sealed is valid base64");
        let recovered_child_write_key = unseal_child_write_key(
            &sealed_child,
            &folder_write_key,
            RECON_CHILD_NODE_ID,
            NodeKind::Folder,
            0,
        )
        .expect("unseal the child write key under the parent write key");
        assert_eq!(
            recovered_child_write_key,
            child_write_key.to_vec(),
            "the child write key is copied verbatim (read-key-rotation-independent, never rotated)"
        );
    }

    /// Test B (D-01b): a node NOT present in the InodeTable fails open to
    /// `None` (never a panic/Err), mirroring `find_ipns_private_key`.
    #[test]
    fn reconstruct_write_body_fails_open_to_none_for_a_non_materialized_node() {
        let table = InodeTable::new();
        assert!(
            reconstruct_write_body(&table, "k51-not-materialized", 3).is_none(),
            "a non-materialized node must fail open to None, not hard-error"
        );
    }

    /// Test C (D-02): a rotation walk that queries grants once per rotated node
    /// (>= 3 nodes here) fetches `GET /shares/sent` at most once, while the
    /// per-node `root_node_id` filter still returns exactly the in-scope grant.
    #[tokio::test]
    async fn rotation_walk_fetches_sent_shares_at_most_once() {
        const OTHER_NODE_ID: &str = "33333333-3333-3333-3333-333333333333";
        let transport = FakeTransport::default();
        transport.seed_sent_shares(vec![
            sent_share_fixture(
                "share-in-scope",
                ROOT_ID,
                "0x04aabbccdd00112233445566778899aabbccddeeff001122334455667788990011",
            ),
            sent_share_fixture("share-other-root", OTHER_NODE_ID, "0x04ff"),
        ]);
        let (owner_pub, owner_priv) = owner_keypair();
        let deps =
            FuseRotationDeps::new(transport.clone(), owner_pub, owner_priv, temp_floor_store());

        for _ in 0..4 {
            let rows = deps
                .query_grants_rooted_at(ROOT_ID)
                .await
                .expect("query_grants_rooted_at must succeed");
            assert_eq!(
                rows.len(),
                1,
                "the root_node_id filter still returns exactly the in-scope grant per node"
            );
            assert_eq!(rows[0].share_id, "share-in-scope");
        }

        assert!(
            transport.collect_sent_shares_count() <= 1,
            "a rotation job must fetch GET /shares/sent at most once (got {})",
            transport.collect_sent_shares_count()
        );
    }
}
