//! The metadata publish driver: turn queued intent ops into published,
//! resolvable records (blueprint/engine.md "Sync core", "Resolve/publish
//! pipeline").
//!
//! One pass rebases the durable queue onto gate-passing state
//! ([`replay`]) and publishes each applied op **referent before reference** —
//! the child's own record first, then the parent that names it — so a partial
//! drain can leave an unreferenced record but never a child ref pointing at a
//! name nothing resolves.
//!
//! Every published record is fed straight back through the adoption gate from
//! the bytes in hand: the write path skips the fetch, never the gate, and the
//! per-name sequence floor advances only as the gate's stage-6 consequence
//! (#817; `gate/floor.rs` stays the only place floors move).
//!
//! This slice drains folder creates only; the first op it cannot publish stops
//! the pass with the op still queued, so FIFO order is never broken.

use core::cell::RefCell;
use std::collections::BTreeSet;

use cipherbox_core::ipns::IpnsName;
use cipherbox_core::kdf;
use cipherbox_core::seal::{ChildRef, NodeKind as CoreNodeKind, ReadBody, open_read_body};
use cipherbox_core::suite::ecdsa::EcdsaVerifier;
use cipherbox_core::suite::x25519::X25519Secret;
use zeroize::Zeroizing;

use crate::api::ApiClient;
use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::facade::{NodeId, NodeKind};
use crate::net::author::{
    AuthorError, AuthoredHead, ENVELOPE_V, EnvelopeAuthoring, author_child_envelope,
    author_scope_root_envelope, new_child,
};
use crate::net::record_publish::{
    HeadBinding, PreflightError, RecordPublishOutcome, RecordPublishRequest, preflight,
    publish_record,
};
use crate::net::{
    AdoptOutcome, Adopter, ChildAdopter, HeldRecord, HeldRecords, LocalHead, RootAdopter,
    assemble_head_envelope,
};
use crate::profile::SyncTimingProfile;
use crate::rotation::derive_write_name;
use crate::seams::{
    CredentialStore, FloorStore, Http, OpId, RecordTransport, Scheduler, SnapshotCache,
    StagingStore,
};
use crate::session::SessionIdentity;
use crate::sync::model::Snapshot;
use crate::sync::op::{Op, OpKind};
use crate::sync::overlay::apply_overlay;
use crate::sync::project::project_root;
use crate::sync::rebase::{DeadLetterReason, decode_queue, replay};
use crate::sync::record::RecordReader;

/// The durable drained-op high-water mark: every op id at or below the stored
/// value has left this device's queue (#860). It rides the sequence-floor
/// namespace, whose contract it is — a durable monotonic-max `u64` under opaque
/// key bytes — under a key the base36 `ipnsName` alphabet cannot spell, so it
/// never collides with a real per-name floor.
pub const DRAINED_OP_FLOOR_KEY: &[u8] = b"cipherbox/drained-op";

/// What one drain pass did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct DrainReport {
    /// Ops whose records published and self-adopted.
    pub(crate) published: Vec<OpId>,
    /// Ops rebase resolved away (already satisfied, or a lost race).
    pub(crate) dropped: Vec<OpId>,
    /// Terminally unrebasable ops, with the reason to surface.
    pub(crate) dead_letters: Vec<(OpId, NodeId, DeadLetterReason)>,
    /// Ops removed as restore residue: already drained on this device, so the
    /// queue that holds them is older than the completion record (#860).
    pub(crate) restore_residue: Vec<OpId>,
    /// Why the pass stopped early, if it did. FIFO is strict: the op stays
    /// queued and the next pass retries it.
    pub(crate) halted: Option<DrainHalt>,
}

impl DrainReport {
    /// Whether the pass left the durable queue exactly as it found it.
    pub(crate) fn is_empty(&self) -> bool {
        self.published.is_empty()
            && self.dropped.is_empty()
            && self.dead_letters.is_empty()
            && self.restore_residue.is_empty()
    }
}

/// Why a drain pass stopped before the queue was empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DrainHalt {
    /// The op kind has no publisher in this slice.
    Unsupported,
    /// Authoring refused to produce the record.
    Author(AuthorError),
    /// The pre-publish dry run refused the authored envelope.
    Preflight(PreflightError),
    /// The publish itself failed, or landed unconfirmed/lost the CAS race.
    Publish(String),
    /// A durable seam or a gate rejection stopped the pass.
    Seam(String),
}

/// The owner-scope material one drain pass publishes under. Every field is
/// borrowed from the live session; the drain zeroizes none of it.
pub(crate) struct DrainScope<'a> {
    /// The vault root node — also the root scope id (the cold-start anchor).
    pub(crate) root: NodeId,
    /// The root's write-plane IPNS name.
    pub(crate) root_name: &'a IpnsName,
    /// The scope read seed per-node read keys derive from.
    pub(crate) scope_read_seed: &'a Zeroizing<[u8; 32]>,
    /// The scope write seed per-node IPNS names and signers derive from.
    pub(crate) write_scope_seed: &'a Zeroizing<[u8; 32]>,
    /// The owner's encryption secret (the root's own seed source, and the op
    /// queue's HPKE-to-self reader).
    pub(crate) enc_secret: &'a X25519Secret,
    /// The contact-anchored owner identity the gate verifies against.
    pub(crate) owner_identity: &'a EcdsaVerifier,
}

/// One drain pass over the durable queue, holding every seam it needs by
/// reference.
pub(crate) struct Drain<'a, T, H: Http, C: CredentialStore, F, S, St, Sch> {
    pub(crate) transport: &'a T,
    pub(crate) api: &'a ApiClient<H, C>,
    pub(crate) floors: &'a F,
    pub(crate) snapshot_cache: &'a S,
    pub(crate) staging: &'a St,
    pub(crate) scheduler: &'a Sch,
    pub(crate) http: &'a H,
    pub(crate) gateway: &'a Gateway,
    pub(crate) profile: &'a SyncTimingProfile,
    /// Seal nonces enter as injected entropy; the drain reads no RNG of its own.
    pub(crate) entropy: &'a RefCell<Box<dyn Entropy>>,
    /// The gate-passing base snapshot, repainted in place on each publish.
    pub(crate) base: &'a RefCell<Snapshot>,
    /// The live held-record set the liveness loop keeps alive.
    pub(crate) held: &'a RefCell<HeldRecords>,
}

/// The scope root's current published state, carried across the ops of one
/// pass so each publish authors onto the previous one.
struct RootState {
    envelope_unknown: Vec<(String, cipherbox_core::codec::Value)>,
    epoch_tag_unknown: Vec<(String, cipherbox_core::codec::Value)>,
    epoch: u64,
    created_at: u64,
    children: Vec<ChildRef>,
    body_unknown: Vec<(String, cipherbox_core::codec::Value)>,
}

impl<T, H, C, F, S, St, Sch> Drain<'_, T, H, C, F, S, St, Sch>
where
    T: RecordTransport + Clone + 'static,
    H: Http,
    C: CredentialStore,
    F: FloorStore,
    S: SnapshotCache,
    St: StagingStore,
    Sch: Scheduler + Clone + 'static,
{
    /// Run one pass: rebase the queue onto gate-passing state and publish every
    /// applied op it can, stopping at the first it cannot.
    pub(crate) async fn run(&self, scope: &DrainScope<'_>) -> DrainReport {
        let mut report = DrainReport::default();
        let queued = match self.queued_ops(scope, &mut report).await {
            Ok(queued) => queued,
            Err(halt) => {
                report.halted = Some(halt);
                return report;
            }
        };
        if let Err(halt) = self.pass(scope, &queued, &mut report).await {
            report.halted = Some(halt);
        }
        if let Err(halt) = self.mark_drained(&queued, &report).await {
            report.halted.get_or_insert(halt);
        }
        report
    }

    async fn pass(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        report: &mut DrainReport,
    ) -> Result<(), DrainHalt> {
        if queued.is_empty() {
            return Ok(());
        }

        let mut root = self.load_root(scope).await?;
        let rebased = {
            let base = self.base.borrow();
            let ops: Vec<Op> = queued.iter().map(|(_, op)| op.clone()).collect();
            let local = apply_overlay(&base, &ops);
            replay(&base, &local, queued)
        };

        for (op_id, reason) in &rebased.dead_letters {
            let target = queued
                .iter()
                .find(|(id, _)| id == op_id)
                .map(|(_, op)| op.target)
                .unwrap_or(scope.root);
            self.retire_op(*op_id).await?;
            report.dead_letters.push((*op_id, target, *reason));
        }
        for (op_id, _) in &rebased.dropped {
            self.retire_op(*op_id).await?;
            report.dropped.push(*op_id);
        }

        for applied in &rebased.applied {
            self.publish_applied(scope, &mut root, applied, &rebased.rebased)
                .await?;
            self.retire_op(applied.op_id).await?;
            report.published.push(applied.op_id);
        }
        Ok(())
    }

    /// This identity's queued ops, minus restore residue: an op at or below the
    /// durable drained-op mark already left this queue once, so the queue it
    /// came back in predates the completion record (#860).
    async fn queued_ops(
        &self,
        scope: &DrainScope<'_>,
        report: &mut DrainReport,
    ) -> Result<Vec<(OpId, Op)>, DrainHalt> {
        let raw = self.staging.queued_ops().await.map_err(seam)?;
        let scan = decode_queue(&RecordReader::new(scope.enc_secret), &raw);
        let drained = self
            .floors
            .sequence_floor(DRAINED_OP_FLOOR_KEY)
            .await
            .map_err(seam)?
            .unwrap_or(0);
        let mut live = Vec::with_capacity(scan.mine.len());
        for (op_id, op) in scan.mine {
            if op_id.0 <= drained {
                self.staging.remove_op(op_id).await.map_err(seam)?;
                report.restore_residue.push(op_id);
                continue;
            }
            live.push((op_id, op));
        }
        Ok(live)
    }

    /// The scope root as currently published: its envelope's carried fields and
    /// its unsealed folder body.
    async fn load_root(&self, scope: &DrainScope<'_>) -> Result<RootState, DrainHalt> {
        let record_bytes = self
            .snapshot_cache
            .get(scope.root_name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .ok_or_else(|| DrainHalt::Seam("no gate-passing root record to publish onto".into()))?;
        let (_sequence, envelope) = assemble_head_envelope(
            self.gateway,
            self.http,
            scope.root_name,
            &record_bytes,
            None,
        )
        .await
        .map_err(|e| DrainHalt::Seam(format!("root head assembly failed: {e}")))?;
        // Encode/decode fail-closed symmetry: this build authors exactly
        // `ENVELOPE_V`, so republishing a newer client's root would silently
        // downgrade `v` — the exact rollback the read-body AAD defends against.
        if envelope.v != ENVELOPE_V {
            return Err(DrainHalt::Seam(format!(
                "root envelope v{} is not authorable by this build",
                envelope.v
            )));
        }
        let read_key = self.node_read_key(scope, &scope.root.0);
        let body = open_read_body(&envelope, &read_key)
            .map_err(|e| DrainHalt::Seam(format!("root read body: {}", e.check())))?;
        let ReadBody::Folder {
            created_at,
            children,
            unknown,
            ..
        } = body
        else {
            return Err(DrainHalt::Seam("scope root is not a folder".into()));
        };
        Ok(RootState {
            envelope_unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            epoch: envelope.epoch,
            created_at,
            children,
            body_unknown: unknown,
        })
    }

    /// Publish one applied op: the new node's own record, then the parent that
    /// names it.
    async fn publish_applied(
        &self,
        scope: &DrainScope<'_>,
        root: &mut RootState,
        applied: &crate::sync::rebase::AppliedOp,
        rebased: &Snapshot,
    ) -> Result<(), DrainHalt> {
        let OpKind::Create {
            parent,
            kind: NodeKind::Folder,
            content: None,
            ..
        } = &applied.op.kind
        else {
            return Err(DrainHalt::Unsupported);
        };
        // Deeper folders need their own parent record authored, which is the
        // next slice; this one publishes creates directly under the scope root.
        if *parent != scope.root {
            return Err(DrainHalt::Unsupported);
        }
        let name = applied
            .effective_name
            .clone()
            .ok_or_else(|| DrainHalt::Seam("a create resolved to no name".into()))?;

        let child_id = applied.op.target;
        let child_name = derive_write_name(scope.write_scope_seed, &child_id.0);
        let child = new_child(
            child_id.0,
            name,
            &child_name,
            CoreNodeKind::Folder,
            rebased.max_link_counter(child_id),
            applied.op.authored_at.0,
        );

        let head = author_child_envelope(EnvelopeAuthoring {
            node_id: child_id.0,
            scope_id: scope.root.0,
            epoch: root.epoch,
            read_key: &self.node_read_key(scope, &child_id.0),
            nonce: &self.nonce()?,
            body: &child.body,
            carried_unknown: Vec::new(),
            carried_epoch_tag_unknown: Vec::new(),
        })
        .map_err(DrainHalt::Author)?;
        let record_bytes = self
            .publish_head(scope, &child_name, &child_id.0, root.epoch, &head)
            .await?;

        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.root.0,
            scope.scope_read_seed.clone(),
            child_id.0,
        );
        adopter.hold_local_head(local_head(&head));
        adopter
            .adopt(&child_name, &record_bytes)
            .await
            .map_err(|e| DrainHalt::Seam(format!("child self-adopt rejected: {e}")))?;
        self.hold(scope, child_id.0, &child_name, &head, record_bytes);

        // Referent published: only now does the parent gain the ref to it.
        root.children.push(child.child_ref);
        self.publish_root(scope, root, applied.op.authored_at.0)
            .await
    }

    /// Re-author and publish the scope root over its current children, then
    /// self-adopt it into the base snapshot.
    async fn publish_root(
        &self,
        scope: &DrainScope<'_>,
        root: &mut RootState,
        modified_at: u64,
    ) -> Result<(), DrainHalt> {
        let read_key = self.node_read_key(scope, &scope.root.0);
        let body = ReadBody::Folder {
            created_at: root.created_at,
            modified_at,
            children: root.children.clone(),
            unknown: root.body_unknown.clone(),
        };
        let head = author_scope_root_envelope(EnvelopeAuthoring {
            node_id: scope.root.0,
            scope_id: scope.root.0,
            epoch: root.epoch,
            read_key: &read_key,
            nonce: &self.nonce()?,
            body: &body,
            carried_unknown: root.envelope_unknown.clone(),
            carried_epoch_tag_unknown: root.epoch_tag_unknown.clone(),
        })
        .map_err(DrainHalt::Author)?;
        let record_bytes = self
            .publish_head(scope, scope.root_name, &scope.root.0, root.epoch, &head)
            .await?;

        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.enc_secret,
            scope.owner_identity,
            scope.root.0,
        );
        adopter.hold_local_head(local_head(&head));
        let AdoptOutcome { adopted, .. } = adopter
            .adopt(scope.root_name, &record_bytes)
            .await
            .map_err(|e| DrainHalt::Seam(format!("root self-adopt rejected: {e}")))?;
        // Cached implies gate-passing: these bytes just cleared all six stages.
        self.snapshot_cache
            .put(scope.root_name.as_str().as_bytes(), &record_bytes)
            .await
            .map_err(seam)?;
        let projected = project_root(scope.root, &adopted, &self.base.borrow());
        *self.base.borrow_mut() = projected;
        self.hold(scope, scope.root.0, scope.root_name, &head, record_bytes);
        Ok(())
    }

    /// Dry-run, publish, and return the signed bytes. Only a confirmed publish
    /// yields bytes to self-adopt: adopting an unconfirmed one would advance the
    /// sequence floor and destroy the idempotent-in-sequence retry (#821).
    async fn publish_head(
        &self,
        scope: &DrainScope<'_>,
        name: &IpnsName,
        node_id: &[u8; 16],
        epoch: u64,
        head: &AuthoredHead,
    ) -> Result<Vec<u8>, DrainHalt> {
        let binding = HeadBinding {
            node_id: *node_id,
            scope_id: scope.root.0,
            epoch,
        };
        let preflighted = preflight(&binding, &self.node_read_key(scope, node_id), head)
            .map_err(DrainHalt::Preflight)?;
        let signer = SessionIdentity::write_name_signer(scope.write_scope_seed, node_id);
        let outcome = publish_record(
            self.transport,
            self.api,
            self.floors,
            self.scheduler,
            self.profile,
            &RecordPublishRequest {
                name,
                signer: &signer,
                head: &preflighted,
                content_cids: Vec::new(),
                min_current_sequence: None,
            },
        )
        .await
        .map_err(|e| DrainHalt::Publish(format!("{e:?}")))?;
        match outcome {
            RecordPublishOutcome::Published { record_bytes, .. } => Ok(record_bytes),
            RecordPublishOutcome::Unconfirmed { sequence, .. } => Err(DrainHalt::Publish(format!(
                "sequence {sequence} published but nothing resolved back"
            ))),
            RecordPublishOutcome::LostRace {
                published_sequence,
                observed_sequence,
            } => Err(DrainHalt::Publish(format!(
                "lost CAS race: published {published_sequence}, observed {observed_sequence}"
            ))),
        }
    }

    /// Insert a just-published record into the live held set so the liveness
    /// loop keeps it alive; the narrow per-name signer is derived here and the
    /// scope seed is not stored (least privilege, `net/liveness.rs`).
    fn hold(
        &self,
        scope: &DrainScope<'_>,
        node_id: [u8; 16],
        name: &IpnsName,
        head: &AuthoredHead,
        record_bytes: Vec<u8>,
    ) {
        self.held.borrow_mut().insert(
            node_id,
            HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer: SessionIdentity::write_name_signer(scope.write_scope_seed, &node_id),
                head_cid: head.cid.clone(),
                content_cids: Vec::new(),
            },
        );
    }

    /// Remove a resolved op from the durable queue.
    async fn retire_op(&self, op_id: OpId) -> Result<(), DrainHalt> {
        self.staging.remove_op(op_id).await.map_err(seam)
    }

    /// Raise the completion mark over this pass's **contiguous** drained prefix.
    /// The mark is a high-water line, so it may only pass ops that have all
    /// left the queue: advancing it over a halted op would make a restored data
    /// dir discard that op as residue instead of publishing it (#860).
    async fn mark_drained(
        &self,
        queued: &[(OpId, Op)],
        report: &DrainReport,
    ) -> Result<(), DrainHalt> {
        let retired: BTreeSet<OpId> = report
            .published
            .iter()
            .chain(&report.dropped)
            .copied()
            .chain(report.dead_letters.iter().map(|(op_id, ..)| *op_id))
            .collect();
        let Some(mark) = queued
            .iter()
            .map_while(|(op_id, _)| retired.contains(op_id).then_some(op_id.0))
            .last()
        else {
            return Ok(());
        };
        self.floors
            .raise_sequence_floor(DRAINED_OP_FLOOR_KEY, mark)
            .await
            .map_err(seam)?;
        Ok(())
    }

    /// The per-node read key (`node-seed` → `read-key`), owned by the caller of
    /// this fn — it is the terminal owner and zeroizes on drop.
    fn node_read_key(&self, scope: &DrainScope<'_>, node_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let node_seed = kdf::node_seed(scope.scope_read_seed, node_id);
        Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
    }

    /// A fresh injected seal nonce. Fails closed: a reused nonce under one key
    /// is a confidentiality break, never a degraded mode.
    fn nonce(&self) -> Result<[u8; 24], DrainHalt> {
        let mut nonce = [0u8; 24];
        self.entropy
            .borrow_mut()
            .fill(&mut nonce)
            .map_err(|e| DrainHalt::Seam(e.message().to_owned()))?;
        Ok(nonce)
    }
}

fn local_head(head: &AuthoredHead) -> LocalHead {
    LocalHead {
        cid: head.cid.clone(),
        block: head.block.clone(),
    }
}

fn seam(err: crate::seams::SeamError) -> DrainHalt {
    DrainHalt::Seam(err.message().to_owned())
}
