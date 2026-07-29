//! The metadata publish driver: turn queued intent ops into published,
//! resolvable records (blueprint/engine.md "Sync core", "Resolve/publish
//! pipeline").
//!
//! One pass rebases the durable queue onto gate-passing state ([`replay`]) and
//! publishes each applied op under one law: **a reference must never outlive
//! its referent** (#819). Child before parent, dest-add before source-remove,
//! and strict FIFO stopping at the first failure — so a partial drain can leave
//! an unreferenced record but never a ref pointing at a name nothing resolves.
//!
//! Every published record is fed straight back through the adoption gate from
//! the bytes in hand: the write path skips the fetch, never the gate, and the
//! per-name sequence floor advances only as the gate's stage-6 consequence
//! (#817; `gate/floor.rs` stays the only place floors move).
//!
//! Out of this slice: content bytes (#868), cross-scope re-seal and the
//! scope-exit rotation trigger (#635), and failure classification (#867) — the
//! first op this pass cannot publish stops it with the op still queued.

use core::cell::RefCell;
use std::collections::BTreeSet;

use cipherbox_core::codec::Value;
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
use crate::gate::floor;
use crate::grants::{UndoDestAdd, undo_dest_add_versioned};
use crate::net::author::{
    AuthoredHead, ENVELOPE_V, EnvelopeAuthoring, author_child_envelope, author_scope_root_envelope,
    new_child,
};
use crate::net::publish::{PublishOutcome, PublishReceipt};
use crate::net::record_publish::{HeadBinding, RecordPublishRequest, preflight, publish_record};
use crate::net::{
    Adopter, ChildAdopter, HeldRecord, HeldRecords, LocalHead, ResolveOutcome, RootAdopter,
    assemble_head_envelope, fanout_get_verify, resolve,
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
use crate::sync::project::project_folder;
use crate::sync::rebase::{AppliedOp, DeadLetterReason, decode_queue, replay};
use crate::sync::record::RecordReader;

/// The staging key holding the drained-op high-water mark: every op id at or
/// below the stored value has left this device's queue (#860).
///
/// It lives in the staging store rather than the floors so the mark and the op
/// ids it names share one durability domain — a store that loses its queue
/// loses the mark with it, instead of retaining a mark that would delete every
/// id the restarted counter reissues. [`orphan_staging_keys`] treats it as
/// referenced so orphan GC never collects it.
///
/// [`orphan_staging_keys`]: crate::sync::staging::orphan_staging_keys
pub const DRAINED_OP_MARK_KEY: &[u8] = b"cipherbox/drained-op";

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

/// A drain pass stopped before the queue was empty. Strict FIFO: the op that
/// stopped it stays queued and the next tick retries it, so the durable queue
/// is the record of the failure. Classifying it — dead-letter thresholds,
/// attempt budgets — is the failure-policy slice's.
struct Halt;

/// The owner-scope material one drain pass publishes under. Every field is
/// borrowed from the live session; the drain zeroizes none of it.
pub(crate) struct DrainScope<'a> {
    /// The vault root node — also the root scope id (the cold-start anchor).
    pub(crate) root: NodeId,
    /// The root's write-plane IPNS name.
    pub(crate) root_name: &'a IpnsName,
    /// The scope read seed per-node read keys derive from.
    pub(crate) read_scope_seed: &'a Zeroizing<[u8; 32]>,
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

/// One folder's current published state, carried across the ops of one pass so
/// each publish authors onto the previous one.
struct FolderState {
    /// The write-plane name this folder publishes under.
    name: IpnsName,
    /// The scope root carries the grant section and authors through a different
    /// envelope path; every other folder is a plain child record.
    is_scope_root: bool,
    envelope_unknown: Vec<(String, Value)>,
    epoch_tag_unknown: Vec<(String, Value)>,
    created_at: u64,
    modified_at: u64,
    children: Vec<ChildRef>,
    body_unknown: Vec<(String, Value)>,
    /// The record sequence this folder was last loaded or published at.
    sequence: u64,
}

/// One node's record as loaded for re-authoring: the envelope fields a
/// republish must carry forward byte-stable (#27 D10) plus the opened body.
struct LoadedNode {
    name: IpnsName,
    sequence: u64,
    envelope_unknown: Vec<(String, Value)>,
    epoch_tag_unknown: Vec<(String, Value)>,
    body: ReadBody,
}

/// One record as this pass published it.
struct Published {
    /// The sequence the self-adopt authenticated.
    sequence: u64,
    /// The live-set entry, held once something references the record.
    held: HeldRecord,
}

/// The scope state one pass mutates: the epoch every record is sealed at, and
/// the folders loaded so far in **ancestor-first load order**, which is also
/// the order the base repaint depends on.
struct Pass {
    epoch: u64,
    folders: Vec<(NodeId, FolderState)>,
}

impl Pass {
    fn holds(&self, folder: NodeId) -> bool {
        self.folders.iter().any(|(id, _)| *id == folder)
    }

    fn insert(&mut self, folder: NodeId, state: FolderState) {
        self.folders.push((folder, state));
    }

    fn folder(&self, folder: NodeId) -> Result<&FolderState, Halt> {
        self.folders
            .iter()
            .find(|(id, _)| *id == folder)
            .map(|(_, state)| state)
            .ok_or(Halt)
    }

    fn folder_mut(&mut self, folder: NodeId) -> Result<&mut FolderState, Halt> {
        self.folders
            .iter_mut()
            .find(|(id, _)| *id == folder)
            .map(|(_, state)| state)
            .ok_or(Halt)
    }
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
        let Ok(queued) = self.queued_ops(scope, &mut report).await else {
            return report;
        };
        let _ = self.pass(scope, &queued, &mut report).await;
        let _ = self.mark_drained(&queued, &report).await;
        report
    }

    async fn pass(
        &self,
        scope: &DrainScope<'_>,
        queued: &[(OpId, Op)],
        report: &mut DrainReport,
    ) -> Result<(), Halt> {
        if queued.is_empty() {
            return Ok(());
        }

        let mut pass = self.open_pass(scope).await?;
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
            self.publish_applied(scope, &mut pass, applied, &rebased.rebased)
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
    ) -> Result<Vec<(OpId, Op)>, Halt> {
        let raw = self.staging.queued_ops().await.map_err(seam)?;
        let scan = decode_queue(&RecordReader::new(scope.enc_secret), &raw);
        // `None` is "no op has ever drained here", not "id 0 drained": the seam
        // contract promises only strictly-increasing ids, so a host that starts
        // at 0 must not lose its first op.
        let drained = self.drained_mark().await?;
        let mut live = Vec::with_capacity(scan.mine.len());
        for (op_id, op) in scan.mine {
            if drained.is_some_and(|mark| op_id.0 <= mark) {
                self.staging.remove_op(op_id).await.map_err(seam)?;
                report.restore_residue.push(op_id);
                continue;
            }
            live.push((op_id, op));
        }
        Ok(live)
    }

    // -----------------------------------------------------------------------
    // Loading the folders a pass authors onto.
    // -----------------------------------------------------------------------

    /// Open a pass anchored on the scope root, whose epoch every record this
    /// pass seals is bound to.
    async fn open_pass(&self, scope: &DrainScope<'_>) -> Result<Pass, Halt> {
        let (root, epoch) = self.load_scope_root(scope).await?;
        let mut pass = Pass {
            epoch,
            folders: Vec::new(),
        };
        self.repaint_folder(scope.root, &root.children, root.sequence, root.modified_at);
        pass.insert(scope.root, root);
        Ok(pass)
    }

    /// The scope root as currently published: its envelope's carried fields and
    /// its unsealed folder body, plus the scope epoch.
    async fn load_scope_root(&self, scope: &DrainScope<'_>) -> Result<(FolderState, u64), Halt> {
        let record_bytes = self
            .snapshot_cache
            .get(scope.root_name.as_str().as_bytes())
            .await
            .map_err(seam)?
            .ok_or(Halt)?;
        let (sequence, envelope) = assemble_head_envelope(
            self.gateway,
            self.http,
            scope.root_name,
            &record_bytes,
            None,
        )
        .await
        .map_err(|_| Halt)?;
        // The cache can be older than the floors — a restored data dir is
        // exactly that (#860). The whole pass anchors here: this record's epoch
        // becomes the epoch every record it publishes is sealed at, so a
        // below-floor anchor would bind a stale epoch into the AAD while the
        // live session seed derives the key — records nobody can open. One
        // at-floor gate call covers both floors (encode-side of the gate's
        // stage-5 reject; security rule 8).
        floor::check(
            self.floors,
            scope.root_name.as_str().as_bytes(),
            &scope.root.0,
            sequence,
            envelope.epoch,
            floor::Strictness::AtFloor,
        )
        .await
        .map_err(|_| Halt)?;
        // Encode/decode fail-closed symmetry: this build authors exactly
        // `ENVELOPE_V`, so republishing a newer client's root would silently
        // downgrade `v` — the exact rollback the read-body AAD defends against.
        if envelope.v != ENVELOPE_V {
            return Err(Halt);
        }
        let read_key = self.node_read_key(scope, &scope.root.0);
        let body = open_read_body(&envelope, &read_key).map_err(|_| Halt)?;
        let ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        } = body
        else {
            return Err(Halt);
        };
        let epoch = envelope.epoch;
        Ok((
            FolderState {
                name: scope.root_name.clone(),
                is_scope_root: true,
                envelope_unknown: envelope.unknown,
                epoch_tag_unknown: envelope.epoch_tag_unknown,
                created_at,
                modified_at,
                children,
                body_unknown: unknown,
                sequence,
            },
            epoch,
        ))
    }

    /// Resolve the scope root through its own gate so the snapshot cache holds
    /// whatever the network now carries. Only a gate-passing adopt writes the
    /// cache, so a rejected or unreachable record leaves last-known-good.
    async fn refresh_scope_root_cache(&self, scope: &DrainScope<'_>) -> Result<(), Halt> {
        let adopter = RootAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.enc_secret,
            scope.owner_identity,
            scope.root.0,
        );
        let resolved = resolve(
            self.transport,
            self.snapshot_cache,
            &adopter,
            scope.root_name,
        )
        .await
        .map_err(seam)?;
        // A gate failure is a trust violation, never staleness: re-authoring on
        // top of last-known-good while the record plane serves a rejected root
        // is exactly the fail-open this rule forbids.
        match resolved.outcome {
            ResolveOutcome::TrustViolation(_) => Err(Halt),
            _ => Ok(()),
        }
    }

    /// Resolve one non-root node's own record through the child pipeline and
    /// open it for re-authoring. The gate decides: only a record that passes
    /// the child bindings, the floors, and the AAD-bound unseal is authorable.
    async fn load_child_node(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        node: NodeId,
    ) -> Result<LoadedNode, Halt> {
        let name = derive_write_name(scope.write_scope_seed, &node.0);
        let adopter = ChildAdopter::new(
            self.gateway,
            self.http,
            self.floors,
            scope.root.0,
            scope.read_scope_seed.clone(),
            node.0,
        );
        let resolved = resolve(self.transport, self.snapshot_cache, &adopter, &name)
            .await
            .map_err(seam)?;
        let record_bytes = match resolved.outcome {
            // An adopt caches its own gate-passing bytes; the other two arms
            // carry theirs.
            ResolveOutcome::Adopted(_) => self
                .snapshot_cache
                .get(name.as_str().as_bytes())
                .await
                .map_err(seam)?
                .ok_or(Halt)?,
            ResolveOutcome::Current { record_bytes } => record_bytes,
            ResolveOutcome::NoUpdate => resolved.last_known_good.ok_or(Halt)?,
            ResolveOutcome::TrustViolation(_) => return Err(Halt),
        };
        let (adopted, envelope) = adopter
            .open_carried_at_floor(&name, &record_bytes)
            .await
            .map_err(|_| Halt)?;
        // The same two rollback guards the root load makes: this build authors
        // exactly `ENVELOPE_V`, and re-sealing a node at another epoch than the
        // scope's would cross the AAD epoch binding.
        if envelope.v != ENVELOPE_V || adopted.epoch != epoch {
            return Err(Halt);
        }
        Ok(LoadedNode {
            name,
            sequence: adopted.sequence,
            envelope_unknown: envelope.unknown,
            epoch_tag_unknown: envelope.epoch_tag_unknown,
            body: adopted.read_body,
        })
    }

    /// Make `folder` and every ancestor between it and the scope root available
    /// in `pass`, loading ancestor-first so the base repaint always has a parent
    /// to hang a projection off.
    async fn ensure_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<(), Halt> {
        if pass.holds(folder) {
            return Ok(());
        }
        let chain = {
            let base = self.base.borrow();
            let mut chain = base.ancestors(folder);
            chain.reverse();
            chain.push(folder);
            chain
        };
        // A folder whose chain does not reach the scope root is not a folder
        // this scope's write plane may author.
        if chain.first() != Some(&scope.root) {
            return Err(Halt);
        }
        for node in chain {
            if pass.holds(node) {
                continue;
            }
            let state = self.load_child_folder(scope, pass.epoch, node).await?;
            self.repaint_folder(node, &state.children, state.sequence, state.modified_at);
            pass.insert(node, state);
        }
        Ok(())
    }

    /// Load one non-root folder's state, refusing a node whose sealed body is
    /// not a folder (a kind transplant).
    async fn load_child_folder(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        folder: NodeId,
    ) -> Result<FolderState, Halt> {
        let loaded = self.load_child_node(scope, epoch, folder).await?;
        let ReadBody::Folder {
            created_at,
            modified_at,
            children,
            unknown,
        } = loaded.body
        else {
            return Err(Halt);
        };
        Ok(FolderState {
            name: loaded.name,
            is_scope_root: false,
            envelope_unknown: loaded.envelope_unknown,
            epoch_tag_unknown: loaded.epoch_tag_unknown,
            created_at,
            modified_at,
            children,
            body_unknown: unknown,
            sequence: loaded.sequence,
        })
    }

    // -----------------------------------------------------------------------
    // The per-op publish plans.
    // -----------------------------------------------------------------------

    /// Publish one applied op's records, referent before reference.
    async fn publish_applied(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
    ) -> Result<(), Halt> {
        match &applied.op.kind {
            OpKind::Create {
                parent,
                kind,
                content: None,
                ..
            } => {
                self.publish_create(scope, pass, applied, rebased, *parent, *kind)
                    .await
            }
            OpKind::Rename { .. } => self.publish_rename(scope, pass, applied).await,
            OpKind::Delete { .. } => self.publish_delete(scope, pass, applied).await,
            OpKind::Relink {
                from_parent,
                new_parent,
                cross_scope: false,
                ..
            } => {
                self.publish_relink(scope, pass, applied, rebased, *from_parent, *new_parent)
                    .await
            }
            OpKind::UpdateContent { .. } => self.publish_update_content(scope, pass, applied).await,
            // Content bytes are #868's; cross-scope re-seal is #635's.
            OpKind::Create { .. } | OpKind::Relink { .. } => Err(Halt),
        }
    }

    /// Create: the new node's own record, then the parent that names it.
    async fn publish_create(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
        parent: NodeId,
        kind: NodeKind,
    ) -> Result<(), Halt> {
        let name = applied.effective_name.clone().ok_or(Halt)?;
        self.ensure_folder(scope, pass, parent).await?;

        let child_id = applied.op.target;
        let child_name = derive_write_name(scope.write_scope_seed, &child_id.0);
        let child = new_child(
            child_id.0,
            name,
            &child_name,
            core_kind(kind),
            rebased.max_link_counter(child_id),
            applied.op.authored_at.0,
        );
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                child_id,
                &child_name,
                false,
                &child.body,
                Vec::new(),
                Vec::new(),
            )
            .await?;

        // Referent published: only now does the parent gain the ref to it.
        pass.folder_mut(parent)?.children.push(child.child_ref);
        self.publish_folder(scope, pass, parent, applied.op.authored_at.0)
            .await?;
        // Held only once the parent names it: a record nothing references is
        // not one the liveness loop should keep alive.
        self.hold(child_id.0, published.held);
        Ok(())
    }

    /// Rename: the name lives only in the parent's child ref
    /// (`crates/core/src/seal/body.rs`), so one parent republish is the whole op.
    async fn publish_rename(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(), Halt> {
        let new_name = applied.effective_name.clone().ok_or(Halt)?;
        let target = applied.op.target;
        let parent = self.published_parent(target)?;
        self.ensure_folder(scope, pass, parent).await?;
        {
            let child = pass
                .folder_mut(parent)?
                .children
                .iter_mut()
                .find(|child| child.id == target.0)
                .ok_or(Halt)?;
            child.name = new_name;
        }
        self.publish_folder(scope, pass, parent, applied.op.authored_at.0)
            .await?;
        Ok(())
    }

    /// Delete: drop the parent's ref. The name itself is retired only on
    /// abandonment (#819 as amended by #824), which is the failure-policy
    /// slice's (#867).
    async fn publish_delete(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let parent = self.published_parent(target)?;
        self.ensure_folder(scope, pass, parent).await?;
        let children = &mut pass.folder_mut(parent)?.children;
        let before = children.len();
        children.retain(|child| child.id != target.0);
        // Removing an absent ref is the op already satisfied, never a publish.
        if children.len() == before {
            return Ok(());
        }
        self.publish_folder(scope, pass, parent, applied.op.authored_at.0)
            .await?;
        Ok(())
    }

    /// Relink: dest-add published before the source-remove, so no window leaves
    /// the child absent from both parents. A source-remove that will not
    /// publish compensates its own dest-add rather than leaving a dual link.
    async fn publish_relink(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
        rebased: &Snapshot,
        from_parent: NodeId,
        dest: NodeId,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let source = self.published_parent(target)?;
        // The op's own presence condition: a source the rebase did not resolve
        // against is a concurrent move this op lost (`sync/op.rs`), and removing
        // from it would clobber the winner.
        if source != from_parent {
            return Err(Halt);
        }
        if source == dest {
            return Ok(());
        }
        // A cycle detaches the whole subtree from the scope root irrecoverably,
        // and no walk can find it again. Release-active, and refused again at
        // rebase so the op dead-letters instead of wedging the queue.
        if dest == target || self.base.borrow().ancestors(dest).contains(&target) {
            return Err(Halt);
        }
        let modified_at = applied.op.authored_at.0;

        self.ensure_folder(scope, pass, source).await?;
        self.ensure_folder(scope, pass, dest).await?;

        // The dest gains the source's own ref, so id/ipnsName/kind and any
        // newer client's fields ride verbatim; only the link counter advances
        // to the winner replay allocated (#33 D5).
        let mut moved = pass
            .folder(source)?
            .children
            .iter()
            .find(|child| child.id == target.0)
            .cloned()
            .ok_or(Halt)?;
        moved.link_counter = rebased
            .winning_link(target)
            .map_or(moved.link_counter.saturating_add(1), |link| {
                link.link_counter
            });

        pass.folder_mut(dest)?.children.push(moved);
        let cas_base = self.publish_folder(scope, pass, dest, modified_at).await?;

        pass.folder_mut(source)?
            .children
            .retain(|child| child.id != target.0);
        if self
            .publish_folder(scope, pass, source, modified_at)
            .await
            .is_err()
        {
            self.compensate_dest_add(scope, pass, dest, source, target, cas_base, modified_at)
                .await?;
            return Err(Halt);
        }
        Ok(())
    }

    /// Undo a published dest-add when the source-remove did not follow it.
    ///
    /// Two fail-closed conditions, because undoing wrongly is the one error the
    /// ordering law cannot absorb — it leaves the child referenced by neither
    /// parent. The source must still name the child (the publish may have
    /// landed and only its self-adopt failed), and the dest must still be at the
    /// sequence our dest-add published; a dest that moved is re-read and the
    /// removal re-derived onto the winner's record rather than replayed over it
    /// (#786).
    #[expect(clippy::too_many_arguments, reason = "one compensation's full state")]
    async fn compensate_dest_add(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        dest: NodeId,
        source: NodeId,
        target: NodeId,
        cas_base: u64,
        modified_at: u64,
    ) -> Result<(), Halt> {
        self.reload_folder(scope, pass, source).await?;
        if !pass
            .folder(source)?
            .children
            .iter()
            .any(|child| child.id == target.0)
        {
            return Ok(());
        }

        let staged = pass.folder(dest)?.children.clone();
        // The version read is the record plane's own, never this device's cache:
        // a cache hit would answer with the bytes we just published and make the
        // compare vacuous.
        let observed = self.observed_sequence(&pass.folder(dest)?.name).await?;
        let drop_target = |children: &[ChildRef]| -> Vec<ChildRef> {
            children
                .iter()
                .filter(|child| child.id != target.0)
                .cloned()
                .collect()
        };
        let children = match undo_dest_add_versioned(&staged, drop_target, cas_base, observed) {
            UndoDestAdd::Removed(children) => children,
            UndoDestAdd::Conflict => {
                self.reload_folder(scope, pass, dest).await?;
                drop_target(&pass.folder(dest)?.children)
            }
        };
        pass.folder_mut(dest)?.children = children;
        self.publish_folder(scope, pass, dest, modified_at).await?;
        Ok(())
    }

    /// The freshest sequence the record plane shows at `name` — the same
    /// record-verify read the publish confirm asserts against. Nothing
    /// resolvable fails closed: the compensation may not treat an unanswered
    /// name as "unchanged".
    async fn observed_sequence(&self, name: &IpnsName) -> Result<u64, Halt> {
        fanout_get_verify(self.transport, name)
            .await
            .map(|(sequence, _)| sequence)
            .ok_or(Halt)
    }

    /// Re-read a folder from the record plane, replacing this pass's copy.
    ///
    /// The scope root is otherwise read from the snapshot cache, which is this
    /// device's own — a compensation that read it there could never see the
    /// concurrent writer it exists to yield to — so the root is re-resolved
    /// through its own gate first.
    async fn reload_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
    ) -> Result<(), Halt> {
        let state = if folder == scope.root {
            self.refresh_scope_root_cache(scope).await?;
            self.load_scope_root(scope).await?.0
        } else {
            self.load_child_folder(scope, pass.epoch, folder).await?
        };
        self.repaint_folder(folder, &state.children, state.sequence, state.modified_at);
        *pass.folder_mut(folder)? = state;
        Ok(())
    }

    /// `updateContent`'s metadata half: a file's own record carries its
    /// `modifiedAt` and version list, and its parent holds no size/mtime mirror
    /// to republish (`crates/core/src/seal/body.rs`). The version this op
    /// stages is the content slice's (#868).
    async fn publish_update_content(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        applied: &AppliedOp,
    ) -> Result<(), Halt> {
        let target = applied.op.target;
        let modified_at = applied.op.authored_at.0;
        // This plan authors the target's own record and nothing else, so a
        // resolution that also needs a parent-side write — the rebase's
        // resurrect arm, which re-links under a resolved name — has no publish
        // plan here and must not report success.
        if applied.effective_name.is_some() {
            return Err(Halt);
        }
        // Same reachability rule every other plan gets from `ensure_folder`: a
        // node no parent links is not one this scope's write plane may author.
        self.ensure_folder(scope, pass, self.published_parent(target)?)
            .await?;
        let loaded = self.load_child_node(scope, pass.epoch, target).await?;
        let ReadBody::File {
            created_at,
            versions,
            unknown,
            ..
        } = loaded.body
        else {
            return Err(Halt);
        };
        let body = ReadBody::File {
            created_at,
            modified_at,
            versions,
            unknown,
        };
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                target,
                &loaded.name,
                false,
                &body,
                loaded.envelope_unknown,
                loaded.epoch_tag_unknown,
            )
            .await?;
        if let Some(node) = self.base.borrow_mut().node_mut(target) {
            node.record_sequence = published.sequence;
            node.mtime = Some(modified_at);
        }
        self.hold(target.0, published.held);
        Ok(())
    }

    /// The parent a node is published under, from the base the pass repaints as
    /// it goes — so an op rebases onto exactly what the ops before it published.
    fn published_parent(&self, node: NodeId) -> Result<NodeId, Halt> {
        self.base.borrow().parent_of(node).ok_or(Halt)
    }

    // -----------------------------------------------------------------------
    // Authoring and publishing one record.
    // -----------------------------------------------------------------------

    /// Re-author and publish one folder over its current children, self-adopt
    /// it, and repaint the base from the result. Returns its new sequence.
    async fn publish_folder(
        &self,
        scope: &DrainScope<'_>,
        pass: &mut Pass,
        folder: NodeId,
        modified_at: u64,
    ) -> Result<u64, Halt> {
        let (name, is_scope_root, body, envelope_unknown, epoch_tag_unknown) = {
            let state = pass.folder(folder)?;
            (
                state.name.clone(),
                state.is_scope_root,
                ReadBody::Folder {
                    created_at: state.created_at,
                    modified_at,
                    children: state.children.clone(),
                    unknown: state.body_unknown.clone(),
                },
                state.envelope_unknown.clone(),
                state.epoch_tag_unknown.clone(),
            )
        };
        let published = self
            .publish_node(
                scope,
                pass.epoch,
                folder,
                &name,
                is_scope_root,
                &body,
                envelope_unknown,
                epoch_tag_unknown,
            )
            .await?;

        let state = pass.folder_mut(folder)?;
        state.sequence = published.sequence;
        state.modified_at = modified_at;
        let children = state.children.clone();
        self.repaint_folder(folder, &children, published.sequence, modified_at);
        self.hold(folder.0, published.held);
        Ok(published.sequence)
    }

    /// Author, publish and self-adopt one node's record. Only a confirmed
    /// publish reaches the gate: adopting an unconfirmed one would advance the
    /// sequence floor and destroy the idempotent-in-sequence retry (#821).
    #[expect(clippy::too_many_arguments, reason = "one record's full authoring")]
    async fn publish_node(
        &self,
        scope: &DrainScope<'_>,
        epoch: u64,
        node: NodeId,
        name: &IpnsName,
        is_scope_root: bool,
        body: &ReadBody,
        carried_unknown: Vec<(String, Value)>,
        carried_epoch_tag_unknown: Vec<(String, Value)>,
    ) -> Result<Published, Halt> {
        let read_key = self.node_read_key(scope, &node.0);
        let nonce = self.nonce()?;
        let authoring = EnvelopeAuthoring {
            node_id: node.0,
            scope_id: scope.root.0,
            epoch,
            read_key: &read_key,
            nonce: &nonce,
            body,
            carried_unknown,
            carried_epoch_tag_unknown,
        };
        let head = if is_scope_root {
            author_scope_root_envelope(authoring, name)
        } else {
            author_child_envelope(authoring)
        }
        .map_err(|_| Halt)?;

        let record_bytes = self
            .publish_head(scope, name, &node.0, epoch, &head)
            .await?;
        let local = local_head(&head);
        let sequence = if is_scope_root {
            let adopter = RootAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                scope.enc_secret,
                scope.owner_identity,
                scope.root.0,
            );
            adopter.hold_local_head(local);
            adopter.adopt(name, &record_bytes).await.map_err(|_| Halt)?
        } else {
            let adopter = ChildAdopter::new(
                self.gateway,
                self.http,
                self.floors,
                scope.root.0,
                scope.read_scope_seed.clone(),
                node.0,
            );
            adopter.hold_local_head(local);
            adopter.adopt(name, &record_bytes).await.map_err(|_| Halt)?
        }
        .adopted
        .sequence;

        // Cached implies gate-passing: these bytes just cleared the gate.
        self.snapshot_cache
            .put(name.as_str().as_bytes(), &record_bytes)
            .await
            .map_err(seam)?;
        Ok(Published {
            sequence,
            held: HeldRecord {
                routing_key: name.as_str().to_owned(),
                record_bytes,
                signer: SessionIdentity::write_name_signer(scope.write_scope_seed, &node.0),
                head_cid: head.cid,
                content_cids: Vec::new(),
            },
        })
    }

    /// Dry-run, publish, and return the signed bytes.
    async fn publish_head(
        &self,
        scope: &DrainScope<'_>,
        name: &IpnsName,
        node_id: &[u8; 16],
        epoch: u64,
        head: &AuthoredHead,
    ) -> Result<Vec<u8>, Halt> {
        let binding = HeadBinding {
            node_id: *node_id,
            scope_id: scope.root.0,
            epoch,
        };
        let preflighted =
            preflight(&binding, &self.node_read_key(scope, node_id), head).map_err(|_| Halt)?;
        // The name and the seed the signer comes from have independent sources
        // for the scope root — the vault pointer's `currentRoot` and the
        // owner-write-blob. Publishing under a name this signer cannot sign for
        // would burn a CAS sequence on a record nothing can verify.
        let signer = SessionIdentity::write_name_signer(scope.write_scope_seed, node_id);
        if IpnsName::from_public_key(&signer.verifying_key()) != *name {
            return Err(Halt);
        }
        let PublishReceipt {
            outcome,
            record_bytes,
        } = publish_record(
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
        .map_err(|_| Halt)?;
        match outcome {
            PublishOutcome::Published { .. } => Ok(record_bytes),
            PublishOutcome::Unconfirmed { .. } => Err(Halt),
            PublishOutcome::LostRace { .. } => Err(Halt),
        }
    }

    /// Merge one folder's published children into the base snapshot.
    fn repaint_folder(
        &self,
        folder: NodeId,
        children: &[ChildRef],
        sequence: u64,
        modified_at: u64,
    ) {
        project_folder(
            &mut self.base.borrow_mut(),
            folder,
            children,
            sequence,
            modified_at,
        );
    }

    /// Insert a just-published record into the live held set so the liveness
    /// loop keeps it alive.
    fn hold(&self, node_id: [u8; 16], held: HeldRecord) {
        self.held.borrow_mut().insert(node_id, held);
    }

    /// Remove a resolved op from the durable queue.
    async fn retire_op(&self, op_id: OpId) -> Result<(), Halt> {
        self.staging.remove_op(op_id).await.map_err(seam)
    }

    /// Raise the completion mark over this pass's **contiguous** drained prefix.
    /// The mark is a high-water line, so it may only pass ops that have all
    /// left the queue: advancing it over a halted op would make a restored data
    /// dir discard that op as residue instead of publishing it (#860).
    async fn mark_drained(&self, queued: &[(OpId, Op)], report: &DrainReport) -> Result<(), Halt> {
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
        // Monotonic by construction: the engine is the single writer, and the
        // mark only ever names ops that have already left the queue.
        let raised = mark.max(self.drained_mark().await?.unwrap_or(0));
        self.staging
            .put_staged_bytes(DRAINED_OP_MARK_KEY, &raised.to_be_bytes())
            .await
            .map_err(seam)
    }

    /// The stored drained-op mark; `None` when nothing has drained on this
    /// device or the stored bytes are not a mark this build wrote.
    async fn drained_mark(&self) -> Result<Option<u64>, Halt> {
        let stored = self
            .staging
            .staged_bytes(DRAINED_OP_MARK_KEY)
            .await
            .map_err(seam)?;
        Ok(stored
            .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
            .map(u64::from_be_bytes))
    }

    /// The per-node read key (`node-seed` → `read-key`), owned by the caller of
    /// this fn — it is the terminal owner and zeroizes on drop.
    fn node_read_key(&self, scope: &DrainScope<'_>, node_id: &[u8; 16]) -> Zeroizing<[u8; 32]> {
        let node_seed = kdf::node_seed(scope.read_scope_seed, node_id);
        Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes())
    }

    /// A fresh injected seal nonce. Fails closed: a reused nonce under one key
    /// is a confidentiality break, never a degraded mode.
    fn nonce(&self) -> Result<[u8; 24], Halt> {
        let mut nonce = [0u8; 24];
        self.entropy
            .borrow_mut()
            .fill(&mut nonce)
            .map_err(|_| Halt)?;
        Ok(nonce)
    }
}

/// Map the facade node kind onto the structurally-identical wire kind.
fn core_kind(kind: NodeKind) -> CoreNodeKind {
    match kind {
        NodeKind::Folder => CoreNodeKind::Folder,
        NodeKind::File => CoreNodeKind::File,
    }
}

fn local_head(head: &AuthoredHead) -> LocalHead {
    LocalHead {
        cid: head.cid.clone(),
        block: head.block.clone(),
    }
}

fn seam(_: crate::seams::SeamError) -> Halt {
    Halt
}
