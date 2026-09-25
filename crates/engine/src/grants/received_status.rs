//! What a bookmarked shared scope root answers with now, as the facts
//! [`super::revocation`] classifies (blueprint/web-client.md "/shared";
//! #25 D3/D4).
//!
//! Revocation is discovered, not delivered, so every fact here comes from a live
//! resolve of the scope root the bookmark names — never from the bookmark's own
//! copy of the permission or the label, which the owner may have superseded.
//! Both anchors are the **verified contact's**: the identity the commitment must
//! verify under, and the encryption subkey the self-locating tag folds in. A key
//! the resolved record supplied would let the record vouch for itself.

use core::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};

use cipherbox_core::error::TrustViolation;
use cipherbox_core::kdf;
use cipherbox_core::seal::{
    AadContext, ChildRef, Permission, ReadBody, STRUCT_TAG_GRANT_BLOB, open_grant_blob,
    open_read_body,
};
use cipherbox_core::suite::ecdsa::{EcdsaVerifier, IDENTITY_PUBLIC_LEN};
use cipherbox_core::suite::secret::SecretBytes;
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};
use futures_channel::mpsc;
use zeroize::Zeroizing;

use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::facade::{
    Event, NodeId, NodeKind, ScopeSeeds, deposit_seed, deposit_write_seed, emit_trust_violation,
};
use crate::gate::floor;
use crate::gate::{
    Candidate, GateError, GateRejection, GateStage, ReaderContext, RejectionReason, SeedBlob,
    adopt, read_cut_epoch_floor, record_cut_epoch_floor, verify_commitment_in_force,
};
use crate::name::validate_name;
use crate::net::rotation::scope_name;
use crate::net::{PointerConsultError, assemble_candidate, fanout_get_verify};
use crate::profile::SyncTimingProfile;
use crate::seams::{
    ContactLabel, FloorStore, Http, RecordTransport, SharerScopedFloorStore, StagingStore,
    UnixMillis,
};
use crate::sync::model::{NodeMeta, node_id_label};
use crate::sync::project::project_folder_partial;
use crate::sync::render::BaseSnapshot;
use crate::sync::tick::{ResolveMode, on_access_refresh_due};

use super::accept::ReceivedShareStore;
use super::accept::{BookmarkKey, LinkHold, ReceivedShare, ReceivedSharesList, ReceivedSharesLock};
use super::contact::Contact;
use super::contact_store::{ContactStore, StagingContactStore};
use super::grafted::{
    BookmarkedPermissions, BookmarkedScopeRoots, ClaimRecord, ContestedNodes, GraftedPlane,
    GraftedSharers, in_own_tree, is_own_scope,
};
use super::invite::EphemeralInvitee;
use super::ledger::{recipient_blinded_tag, self_locate_signed};
use super::link_read::{committed_link_entry, held_scope_root};
use super::received_share_store::StagingReceivedShareStore;
use super::revocation::{ResolutionClass, ResolutionFacts, classify};

/// How many shared scope roots one pass resolves. Each costs a fan-out GET and
/// a head fetch, and a bookmarked set may hold
/// [`MAX_RECEIVED_SHARES`](super::accept::MAX_RECEIVED_SHARES) — the rest keep
/// their held verdict and stay due for the next pass.
const MAX_RESOLVES_PER_PASS: usize = 16;

/// One shared scope's last resolution verdict, and when the pass that reached
/// it ran — the stamp the refresh damper paces against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReceivedVerdict {
    /// What the resolve classified.
    pub class: ResolutionClass,
    /// When the pass that reached it ran.
    pub at: UnixMillis,
    /// What the owner's live commitment last permitted this vault in the scope.
    /// The bookmark's own copy is the accept's snapshot of it, and a downgrade
    /// republishes the demoted set without delivering a fresh pointer.
    pub permission: Permission,
}

/// The durable bars a verdict on one bookmarked shared scope is measured
/// against, both read under the sharer-scoped view of the floor store.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SharedScopeFloors {
    pub epoch: u64,
    pub cut_epoch: u64,
}

/// Each bookmarked shared scope's latest verdict, keyed the way the bookmark
/// itself is ([`BookmarkKey`]). Two sharers may hold one scope id, and the id
/// alone would collapse their rows onto one verdict cell.
pub(crate) type ReceivedVerdicts = BTreeMap<BookmarkKey, ReceivedVerdict>;

/// The permission a host reports for `share`: the owner's live commitment as of
/// the last resolve, or the accept-time copy before any pass reaches one.
pub(crate) fn live_permission(verdicts: &ReceivedVerdicts, share: &ReceivedShare) -> Permission {
    verdicts
        .get(&share.key())
        .map_or(share.permission, |verdict| verdict.permission)
}

/// Where an adopted shared scope lands: the render tree a focus reads
/// (blueprint/web-client.md "/shared": browsing a shared scope is the same
/// browser over the same snapshot), the per-scope read-seed cache the leg below
/// its root reads with, and the repaint signal a merge emits.
pub(crate) struct ScopeRender<'a> {
    /// The last-known-good render tree.
    pub base: &'a BaseSnapshot,
    /// Scope id -> the recovered read scope seed.
    pub read_seeds: &'a RefCell<ScopeSeeds>,
    /// Scope id -> the recovered write scope seed, which a write grantee's own
    /// drain pass derives every name and signer it publishes under.
    pub write_seeds: &'a RefCell<ScopeSeeds>,
    /// This vault's own root scope, and the scope roots a boundary walk proved
    /// below it — the pair [`is_own_scope`] decides a grafted deposit against,
    /// so a sharer-authored `scopeId` cannot land on an own scope's cell.
    pub own_root: &'a [u8; 16],
    /// See [`own_root`](Self::own_root).
    pub own_descendants: &'a RefCell<BTreeSet<NodeId>>,
    /// Which identity granted each scope root the tree holds by graft — the
    /// floor namespace every leg below such a root must read in.
    pub grafted_sharers: &'a RefCell<GraftedSharers>,
    /// The bookmarked scope-root set every leg below a grafted root applies its
    /// cross-plane rule against ([`GraftedPlane`]).
    pub scope_roots: &'a RefCell<BookmarkedScopeRoots>,
    /// What each bookmarked scope's accepted grant permits this vault to do,
    /// which is what a host gates its write affordances on
    /// ([`BookmarkedPermissions`]).
    pub permissions: &'a RefCell<BookmarkedPermissions>,
    /// What each renderable scope's body last named — the per-node claim this
    /// pass folds its scope-root bodies into, and every leg below a grafted
    /// root reads.
    pub claims: &'a RefCell<ClaimRecord>,
    /// The host event stream.
    pub events: &'a mpsc::UnboundedSender<Event>,
}

/// One resolved scope root this pass may render: the bookmark it resolved from,
/// and what its body named.
struct Opened<'a> {
    share: &'a ReceivedShare,
    children: Vec<ChildRef>,
    sequence: u64,
    modified_at: u64,
}

/// Fold this pass's scope-root bodies into the per-node claim, drop every body
/// the record refuses, and answer with the ids more than one scope names.
///
/// A scope this pass did not open keeps the entry its last opened body wrote, so
/// a fresh body does not take an id from a scope this pass could not reach. The
/// folder bodies the focus leg recorded are separate entries, so a root body
/// replaces the root's claim and nothing else.
///
/// The fresh root bodies land **before** the prune, which is what lets
/// [`ClaimRecord::retain_live_bodies`] answer over what this pass's own bodies
/// name.
fn claim_contest(
    opened: &mut Vec<Opened<'_>>,
    renderable: &BTreeSet<[u8; 16]>,
    render: &ScopeRender<'_>,
) -> ContestedNodes {
    let mut claims = render.claims.borrow_mut();
    opened.retain(|open| {
        let share = open.share;
        match claims.record(share.scope_id, share.scope_id, &open.children) {
            Ok(()) => true,
            Err(over_full) => {
                emit_trust_violation(
                    render.events,
                    grafted_root_name(&share.display_name, NodeId(share.scope_id)).as_str(),
                    over_full,
                );
                false
            }
        }
    });
    claims.retain_live_bodies(renderable);
    claims.contested().clone()
}

/// Depart every contested id the render tree still holds on a grafted plane.
///
/// A merge speaks only for a plane this pass re-opened, so a plane that stops
/// answering would keep an id the contest has since taken from it. A bookmarked
/// scope root is spared: it is a plane, not a node a body wins. So is a node of
/// this vault's own tree, which this vault authors.
fn depart_contested(contested: &ContestedNodes, render: &ScopeRender<'_>) -> bool {
    let scope_roots = render.scope_roots.borrow();
    let mut base = render.base.borrow_mut();
    let mut departed = false;
    for id in contested.difference(&scope_roots).map(|id| NodeId(*id)) {
        if base.contains(id) && !in_own_tree(&base, id) {
            base.remove_deleted(id);
            departed = true;
        }
    }
    departed
}

/// The name a grafted scope root renders under, and the label the `/shared` row
/// carries.
///
/// The sharer authors the label, so it is held to the node-name law
/// ([`validate_name`]) before it reaches the render tree. Refusing the share
/// instead is not open to us — the recipient must still reach the folder — and
/// the label binds nothing, so the node-id fallback costs no reachability.
pub(crate) fn grafted_root_name(display_name: &str, root: NodeId) -> Zeroizing<String> {
    match validate_name(display_name) {
        Ok(()) => Zeroizing::new(display_name.to_owned()),
        Err(_) => Zeroizing::new(node_id_label(root)),
    }
}

/// Report a gate refusal of the record `share`'s scope root answered with.
fn report_refusal(
    events: &mpsc::UnboundedSender<Event>,
    share: &ReceivedShare,
    rejection: &GateRejection,
) {
    emit_trust_violation(
        events,
        grafted_root_name(&share.display_name, NodeId(share.scope_id)).as_str(),
        rejection,
    );
}

/// Merge one opened scope root into the render tree, under the cross-plane rule
/// its plane applies ([`GraftedPlane`]).
fn merge_grafted(open: &Opened<'_>, contested: &ContestedNodes, render: &ScopeRender<'_>) {
    let share = open.share;
    let root = NodeId(share.scope_id);
    let scope_roots = render.scope_roots.borrow();
    let mut base = render.base.borrow_mut();
    let split = GraftedPlane {
        scope_id: share.scope_id,
        scope_roots: &scope_roots,
        contested,
    }
    .split(&base, &open.children);
    // The scope root has no parent here to name it, so the pointer's label is
    // the only name a browse can show.
    let label = grafted_root_name(&share.display_name, root);
    let renamed = match base.node_mut(root) {
        Some(meta) if meta.name() != *label => {
            meta.rename(label.as_str());
            true
        }
        Some(_) => false,
        None => {
            let mut meta = NodeMeta::new(root, label.as_str(), NodeKind::Folder);
            meta.ipns_name = Some(share.scope_root_name.clone());
            base.upsert_node(meta);
            true
        }
    };
    if project_folder_partial(
        &mut base,
        root,
        &split.linkable,
        &split.withheld,
        open.sequence,
        open.modified_at,
    ) || renamed
    {
        let _ = render.events.unbounded_send(Event::SnapshotUpdated);
    }
}

/// What one pass decided about a share: the verdict, the record a browse of it
/// opens, the ephemeral key a link-held read used, and the change that read
/// owes the bookmark's link hold.
struct Classified {
    class: ResolutionClass,
    resolved: Option<(Candidate, SharedScopeFloors)>,
    /// The link key this pass read with. `None` on the personal path.
    link: Option<EphemeralInvitee>,
    hold_change: Option<HoldChange>,
}

impl Classified {
    /// A pass that reached no verdict on the record.
    fn unresolvable() -> Self {
        Self {
            class: ResolutionClass::Unresolvable,
            resolved: None,
            link: None,
            hold_change: None,
        }
    }

    /// Whether the pass read the personal tag of a resolved record.
    fn personal(&self) -> bool {
        self.resolved.is_some() && self.link.is_none()
    }
}

/// The class of a link-held read whose link entry has `deadline`. The owner's
/// sweep cuts a link at its deadline, so a link gone after it reads as expired
/// too (ADR 0025 D5).
fn link_class(
    class: ResolutionClass,
    deadline: Option<UnixMillis>,
    now: UnixMillis,
) -> ResolutionClass {
    if now.reached(deadline) {
        ResolutionClass::Expired
    } else {
        class
    }
}

/// A change a pass makes to a bookmark, applied by key to the list as stored
/// when the pass ends.
enum HoldChange {
    /// A personal blob opened, so the link keys go (ADR 0024 D2).
    Drop(BookmarkKey),
    /// The link entry's deadline differs from the last verified one.
    Deadline(BookmarkKey, Option<UnixMillis>),
    /// The scope pointer vouched for another scope root.
    Heal(BookmarkKey, Vec<u8>),
}

impl HoldChange {
    fn apply(self, list: &mut ReceivedSharesList) {
        match self {
            Self::Drop(key) => {
                list.drop_link(&key);
            }
            Self::Deadline(key, deadline) => list.set_link_deadline(&key, deadline),
            Self::Heal(key, root) => list.heal_root_name(&key, root),
        }
    }
}

/// What a held bookmark's scope pointer vouched for this pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PointerVerdict {
    /// The re-point object opened and verified.
    Vouched,
    /// No pointer record stands at the name.
    Absent,
    /// No endpoint answered.
    Unavailable,
    /// The re-point object was refused, which is reported.
    Rejected,
}

/// The pair a grant blob self-locates and opens under: the sharer's contact,
/// and this device's key or the link's ephemeral key.
#[derive(Clone, Copy)]
struct BlobKeys<'a> {
    contact: &'a Contact,
    enc_secret: &'a X25519Secret,
}

/// The seams one received-share resolve reads, plus this device's own
/// encryption subkey — the self-locating tag's other half. Borrowed: the
/// session stays its terminal owner.
pub(crate) struct ReceivedShareStatus<'a, T, H, F> {
    /// The record plane the scope root resolves over.
    pub transport: &'a T,
    /// The content read source for the record's head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam that fetch rides.
    pub http: &'a H,
    /// The durable floors — the read-epoch floor an epoch lag is measured
    /// against.
    pub floors: &'a F,
    /// This device's encryption subkey.
    pub enc_secret: &'a X25519Secret,
    /// This account's contact-label seed — what a share's sharer is labelled
    /// under before it keys that scope's durable epoch floor.
    pub contact_label_seed: &'a SecretBytes,
    /// Held across the tail's load, change and persist of the list.
    pub list_lock: &'a ReceivedSharesLock,
    /// How this pass paces its re-resolves
    /// ([`refresh`](ReceivedShareStatus::refresh)).
    pub mode: ResolveMode,
}

impl<T: RecordTransport, H: Http, F: FloorStore> ReceivedShareStatus<'_, T, H, F> {
    /// Re-classify the bookmarked shared scope roots that are due, into
    /// `verdicts`.
    ///
    /// The poll leg is paced by [`on_access_refresh_due`], the same damper the
    /// focus window's folder leg uses; a forced pass ([`ResolveMode::NoCache`])
    /// re-resolves every share. This leg alone resolves a grafted scope root —
    /// the focus window drops it, because a scope's own root never resolves
    /// through the child gate — so a damped forced pass would report a listing
    /// it did not re-read (blueprint/engine.md "Sync core").
    ///
    /// Both legs are capped at [`MAX_RESOLVES_PER_PASS`]: a pass over a full
    /// bookmark list would not finish inside its own tick, and the legs after it
    /// would never run. A verdict not re-reached this pass is carried forward,
    /// and the least recently refreshed bookmarks go first.
    ///
    /// Rebuilt each pass, so a share the list no longer holds leaves no verdict
    /// behind. A store failure leaves the last pass's verdicts standing rather
    /// than blanking them.
    pub(crate) async fn refresh<St, E>(
        &self,
        staging: &St,
        entropy: &RefCell<E>,
        verdicts: &RefCell<ReceivedVerdicts>,
        render: &ScopeRender<'_>,
        now: UnixMillis,
        profile: &SyncTimingProfile,
    ) where
        St: StagingStore,
        E: Entropy,
    {
        let store = StagingReceivedShareStore::new(staging, self.enc_secret, entropy);
        let Ok(mut received) = store.load().await else {
            return;
        };
        // Ahead of the contact book, which costs one signature verify per entry
        // to decode: a vault that has accepted nothing pays none of it.
        if received.iter().next().is_none() {
            verdicts.borrow_mut().clear();
            render.grafted_sharers.borrow_mut().clear();
            render.scope_roots.borrow_mut().clear();
            render.permissions.borrow_mut().clear();
            render.claims.borrow_mut().clear();
            return;
        }
        let Ok(contacts) = StagingContactStore::new(staging, self.enc_secret, entropy)
            .contacts()
            .await
        else {
            return;
        };
        // Indexed once: `to_sec1` re-encodes a point, so a scan per share would
        // pay that per (share, contact) pair.
        let by_identity: BTreeMap<[u8; IDENTITY_PUBLIC_LEN], &Contact> = contacts
            .iter()
            .map(|contact| (contact.identity_pk().to_sec1(), contact))
            .collect();

        let due = |key: &BookmarkKey| {
            self.mode == ResolveMode::NoCache
                || verdicts
                    .borrow()
                    .get(key)
                    .is_none_or(|held| on_access_refresh_due(now, held.at, profile))
        };
        // One budget, spent least recently refreshed first, so capped passes
        // reach every bookmark in turn. A held bookmark spends one resolve on
        // its scope pointer and one on its scope root.
        let mut due_keys: Vec<(Option<UnixMillis>, BookmarkKey)> = received
            .iter()
            .map(ReceivedShare::key)
            .filter(due)
            .map(|key| (verdicts.borrow().get(&key).map(|held| held.at), key))
            .collect();
        due_keys.sort_by_key(|(at, _)| *at);
        let mut budget = MAX_RESOLVES_PER_PASS;
        let scheduled: BTreeSet<BookmarkKey> = due_keys
            .into_iter()
            .map(|(_, key)| key)
            .map_while(|key| {
                let cost = 1 + usize::from(received.link_hold(&key).is_some());
                budget = budget.checked_sub(cost)?;
                Some(key)
            })
            .collect();
        let (pointers, heals) = self
            .follow_held_pointers(&received, &by_identity, &scheduled, render.events)
            .await;
        let mut hold_changes: Vec<HoldChange> = Vec::new();
        for (key, root) in heals {
            received.heal_root_name(&key, root.clone());
            hold_changes.push(HoldChange::Heal(key, root));
        }

        // A browse addresses a scope by its id alone, but the id is the sharer's
        // to author: `granted_scope_roots` decides ambiguity over every bookmark,
        // and an id two of them claim answers for neither. Only what survives
        // that rule may reach the render tree.
        let renderable: BTreeSet<[u8; 16]> = received
            .granted_scope_roots()
            .into_iter()
            .map(|granted| granted.scope_id)
            .collect();
        *render.scope_roots.borrow_mut() = received.iter().map(|share| share.scope_id).collect();
        // Rebuilt each pass, like the verdicts. It covers every renderable
        // scope and not only the ones this pass grafts: a revoked share keeps
        // the listing it last rendered, and the leg below it must keep reading
        // the floor that revoked it.
        *render.grafted_sharers.borrow_mut() = received
            .iter()
            .filter(|share| renderable.contains(&share.scope_id))
            .map(|share| (share.scope_id, share.sharer_identity_pk))
            .collect();

        let mut refreshed = BTreeMap::new();
        let mut opened: Vec<Opened<'_>> = Vec::new();
        for share in received.iter() {
            let key = share.key();
            let held = verdicts.borrow().get(&key).copied();
            // A link-held read renders only under a root this pass vouched for
            // through the pointer (ADR 0024 D5), so an unanswered pointer keeps
            // the last verdict.
            let pointer = pointers.get(&key).copied();
            if !scheduled.contains(&key) || pointer == Some(PointerVerdict::Unavailable) {
                if let Some(held) = held {
                    refreshed.insert(key, held);
                }
                continue;
            }
            // Both anchors are contact-held, so a forgotten sharer leaves no
            // verified identity to hold the record to.
            let carried = held.map_or(share.permission, |held| held.permission);
            let hold = received.link_hold(&key);
            let contact = by_identity.get(&share.sharer_identity_pk);
            let (Some(contact), None | Some(PointerVerdict::Vouched)) = (contact, pointer) else {
                let class = match (hold, pointer) {
                    (_, Some(PointerVerdict::Rejected)) | (None, _) => {
                        ResolutionClass::Unresolvable
                    }
                    (Some(hold), _) => {
                        link_class(ResolutionClass::Unresolvable, hold.deadline, now)
                    }
                };
                refreshed.insert(
                    key,
                    ReceivedVerdict {
                        class,
                        at: now,
                        permission: carried,
                    },
                );
                continue;
            };
            // One resolve serves both legs: the verdict this row renders, and
            // the subtree a browse of it opens.
            let classified = self.classified(share, contact, hold, render.events).await;
            let personal = classified.personal();
            let Classified {
                mut class,
                resolved,
                link,
                hold_change,
            } = classified;
            if let Some(hold) = hold.filter(|_| !personal) {
                let deadline = match &hold_change {
                    Some(HoldChange::Deadline(_, fresh)) => *fresh,
                    _ => hold.deadline,
                };
                class = link_class(class, deadline, now);
            }
            hold_changes.extend(hold_change);
            let enc_secret = link
                .as_ref()
                .map_or(self.enc_secret, EphemeralInvitee::enc_secret);
            let mut permission = carried;
            if class == ResolutionClass::Granted {
                if let Some((candidate, floors)) = &resolved {
                    // Only a `Granted` verdict has cleared the commitment's
                    // whole of stage 2, so only there is the committed
                    // permission the owner's word rather than the record's.
                    if let Some(committed) =
                        self.committed_permission(candidate, share, contact, enc_secret)
                    {
                        permission = committed;
                    }
                    if renderable.contains(&share.scope_id) {
                        match self
                            .open(
                                candidate,
                                share,
                                BlobKeys {
                                    contact,
                                    enc_secret,
                                },
                                floors.epoch,
                                permission,
                                render,
                            )
                            .await
                        {
                            Ok(Some(open)) => {
                                // The personal blob opened, so the link keys go
                                // (ADR 0024 D2).
                                if hold.is_some() && personal {
                                    hold_changes.push(HoldChange::Drop(key));
                                }
                                opened.push(open);
                            }
                            Ok(None) => {}
                            Err(rejection) => {
                                report_refusal(render.events, share, &rejection);
                                class = ResolutionClass::Unresolvable;
                            }
                        }
                    }
                }
            }
            // A sharer authors the id it bookmarks under, so none of this
            // reaches a scope this vault owns.
            let grafted = !is_own_scope(
                render.own_root,
                &render.own_descendants.borrow(),
                &share.scope_id,
            );
            // The live set commits this device nowhere, so the capability lapses
            // on the pass that sees that rather than at a read-epoch floor a
            // write-only cut never raises. In memory only: the commitment covers
            // each row and not the blob set, so a stripped blob must destroy
            // nothing at rest ([`ResolutionClass::RevocationSignal`]), and a
            // later granted pass re-deposits both seeds.
            if grafted
                && matches!(
                    class,
                    ResolutionClass::RevocationSignal | ResolutionClass::Expired
                )
            {
                permission = Permission::Read;
                render.read_seeds.borrow_mut().remove(&share.scope_id);
            }
            // The cached write seed is held under the live permission alone, on
            // every arm — including the ones that reach no blob at all, where
            // [`Self::open`] never runs to drop it.
            if grafted && permission != Permission::Write {
                render.write_seeds.borrow_mut().remove(&share.scope_id);
            }
            refreshed.insert(
                key,
                ReceivedVerdict {
                    class,
                    at: now,
                    permission,
                },
            );
        }
        *render.permissions.borrow_mut() = received
            .iter()
            .map(|share| (share.scope_id, live_permission(&refreshed, share)))
            .collect();
        *verdicts.borrow_mut() = refreshed;

        let contested = claim_contest(&mut opened, &renderable, render);
        if depart_contested(&contested, render) {
            let _ = render.events.unbounded_send(Event::SnapshotUpdated);
        }
        for open in &opened {
            merge_grafted(open, &contested, render);
        }
        drop(opened);

        // The join and the accept write this list across this pass's awaits, so
        // the changes land by key on the list as stored now. Best effort: a
        // failed persist leaves the stored list one pass behind, and the next
        // pass reaches the same changes from the record.
        if !hold_changes.is_empty() {
            let _list_guard = self.list_lock.lock().await;
            if let Ok(mut stored) = store.load().await {
                for change in hold_changes {
                    change.apply(&mut stored);
                }
                let _ = store.persist(&stored).await;
            }
        }
    }

    /// Follow the scope pointer of every scheduled bookmark that holds link
    /// keys (ADR 0024 D5 step 3). Answers each one's verdict, and the scope
    /// root each vouched-for bookmark must move to. A refused re-point object
    /// is a trust verdict, reported here.
    async fn follow_held_pointers(
        &self,
        received: &ReceivedSharesList,
        by_identity: &BTreeMap<[u8; IDENTITY_PUBLIC_LEN], &Contact>,
        scheduled: &BTreeSet<BookmarkKey>,
        events: &mpsc::UnboundedSender<Event>,
    ) -> (
        BTreeMap<BookmarkKey, PointerVerdict>,
        Vec<(BookmarkKey, Vec<u8>)>,
    ) {
        let mut verdicts = BTreeMap::new();
        let mut heals = Vec::new();
        for share in received.iter() {
            let key = share.key();
            let (Some(hold), Some(contact), true) = (
                received.link_hold(&key),
                by_identity.get(&share.sharer_identity_pk),
                scheduled.contains(&key),
            ) else {
                continue;
            };
            let verdict = match held_scope_root(
                self.transport,
                &self.sharer_floors(share),
                share,
                hold,
                &contact.identity_pk(),
            )
            .await
            {
                Ok(Some(root)) => {
                    let root = root.as_str().as_bytes();
                    if root != share.scope_root_name {
                        heals.push((key, root.to_vec()));
                    }
                    PointerVerdict::Vouched
                }
                Ok(None) => PointerVerdict::Absent,
                Err(PointerConsultError::Unavailable) => PointerVerdict::Unavailable,
                Err(PointerConsultError::Rejected) => {
                    emit_trust_violation(
                        events,
                        grafted_root_name(&share.display_name, NodeId(share.scope_id)).as_str(),
                        "the scope pointer's re-point object was refused",
                    );
                    PointerVerdict::Rejected
                }
            };
            verdicts.insert(key, verdict);
        }
        (verdicts, heals)
    }

    /// What the owner's live commitment permits this vault in `share`'s scope,
    /// read at the blinded tag the resolved record's own name folds in.
    ///
    /// The caller must have classified the record `Granted`, which is the whole
    /// of the gate's stage 2 over this commitment plus a blob at that tag.
    fn committed_permission(
        &self,
        candidate: &Candidate,
        share: &ReceivedShare,
        contact: &Contact,
        enc_secret: &X25519Secret,
    ) -> Option<Permission> {
        let tag = recipient_blinded_tag(enc_secret, &contact.enc_subkey(), &share.scope_root_name)?;
        candidate
            .grant_section
            .commitment
            .entries
            .iter()
            .find(|entry| entry.tag == tag)
            .map(|entry| entry.permission)
    }

    /// `share`'s floors, filed under the identity that granted it.
    ///
    /// The sharer authors its own `scopeId`, so a floor read or raised under the
    /// plain id reaches every other sharer's scope of that id and this vault's
    /// own anchored root scope.
    fn sharer_floors(&self, share: &ReceivedShare) -> SharerScopedFloorStore<'_, F> {
        SharerScopedFloorStore::granted_by(
            self.floors,
            ContactLabel::of(self.contact_label_seed, &share.sharer_identity_pk),
        )
    }

    /// The verdict `share`'s row renders this pass, with the record a browse of
    /// the row opens.
    ///
    /// A commitment that clears the whole of the gate's stage 2 — which is what
    /// [`facts_from`] reports as `owner_signed_record`, at the bookmarked scope
    /// — raises this device's cut-epoch floor here. It is the one floor advance
    /// the record plane makes with no unseal, and the cut epoch is the only
    /// field that makes it
    /// ([ADR 0014](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0014-a-verified-commitments-cut-epoch-raises-the-floor-without-an-unseal.md)).
    /// It is also the only raise a recipient the owner cut can reach: holding no
    /// blob in the post-cut set, that device adopts no post-cut record, so a
    /// replayed pre-cut set would re-grant its row for as long as it is served.
    ///
    /// `contact` must be the one `share.sharer_identity_pk` names, because that
    /// field is what keys the floor the commitment raises: a raise the two
    /// disagree on would restrict a scope this identity never granted.
    ///
    /// A share that holds link keys reads its personal tag first, and reads the
    /// link tag only while no committed personal blob stands (ADR 0024 D2). On
    /// the link path the tag must name a link entry; the caller decides its
    /// deadline (ADR 0024 D5 step 6).
    async fn classified(
        &self,
        share: &ReceivedShare,
        contact: &Contact,
        hold: Option<&LinkHold>,
        events: &mpsc::UnboundedSender<Event>,
    ) -> Classified {
        let Some((candidate, floors)) = self.resolved(share, events).await else {
            return Classified::unresolvable();
        };
        let sharer_enc = contact.enc_subkey();
        let link = match hold {
            Some(hold) if !personal_blob_opens(&candidate, share, self.enc_secret, &sharer_enc) => {
                // A stored secret that is no scalar reads nothing.
                match EphemeralInvitee::from_secret(hold.invite_secret.as_bytes()) {
                    Ok(invitee) => Some(invitee),
                    Err(_) => return Classified::unresolvable(),
                }
            }
            _ => None,
        };
        let enc_secret = link
            .as_ref()
            .map_or(self.enc_secret, EphemeralInvitee::enc_secret);
        let facts = match facts_from(
            &candidate,
            share,
            enc_secret,
            &contact.identity_pk(),
            &sharer_enc,
            floors,
        ) {
            Ok(facts) => facts,
            Err(rejection) => {
                report_refusal(events, share, &rejection);
                return Classified::unresolvable();
            }
        };
        let cut_epoch = candidate.grant_section.commitment.cut_epoch;
        // Only a cut this device has not recorded is written, so a scope in its
        // steady state costs the store nothing. A cut this pass could not record
        // is not a bar this device holds, and the next pass would measure a
        // replayed pre-cut set against the floor this one failed to raise — so
        // the failure reaches no verdict, as an unreadable floor does above.
        if facts.owner_signed_record
            && cut_epoch > floors.cut_epoch
            && record_cut_epoch_floor(&self.sharer_floors(share), &share.scope_id, cut_epoch)
                .await
                .is_err()
        {
            return Classified::unresolvable();
        }
        let mut class = classify(&facts);
        let mut hold_change = None;
        if let (Some(invitee), Some(hold)) = (&link, hold) {
            let entry =
                recipient_blinded_tag(invitee.enc_secret(), &sharer_enc, &share.scope_root_name)
                    .and_then(|tag| committed_link_entry(&candidate, &tag));
            match entry {
                Some(entry) => {
                    let deadline = entry.deadline.map(|deadline| UnixMillis(deadline.get()));
                    if deadline != hold.deadline {
                        hold_change = Some(HoldChange::Deadline(share.key(), deadline));
                    }
                }
                // A tag the owner committed as anything but a link entry
                // grants a link holder nothing.
                None => class = ResolutionClass::RevocationSignal,
            }
        }
        Classified {
            class,
            resolved: Some((candidate, floors)),
            link,
            hold_change,
        }
    }

    /// The record `share`'s scope root answers with now, and the durable bars
    /// every verdict on it is measured against. `None` is never a removal: it
    /// is absence — an unparsable bookmark, an unresolvable name, a record whose
    /// blocks a seam could not fetch, or a floor this pass could not read — or a
    /// gate refusal (a replay below the sequence floor, a record the assembly
    /// rejects), which is reported on `events` first.
    async fn resolved(
        &self,
        share: &ReceivedShare,
        events: &mpsc::UnboundedSender<Event>,
    ) -> Option<(Candidate, SharedScopeFloors)> {
        // A floor this pass could not read is availability, not a verdict: with
        // no floor neither bar can fire, so a superseded or stale record would
        // read as granted. Absent (`Ok(None)`) is a genuine zero.
        let sharer_floors = self.sharer_floors(share);
        let epoch = floor::read_epoch_floor(&sharer_floors, &share.scope_id)
            .await
            .ok()?
            .unwrap_or(0);
        let cut_epoch = read_cut_epoch_floor(&sharer_floors, &share.scope_id)
            .await
            .ok()?;

        let name = scope_name(&share.scope_root_name).ok()?;
        let (verified, record_bytes) = fanout_get_verify(self.transport, &name).await?;
        // Fan-out has no memory — it answers with the best of what endpoints
        // served. A suppressing relay could otherwise re-serve the record that
        // still committed this device and pin the verdict at `Granted`. Read the
        // durable bar only; a body this pass never unsealed may not raise it
        // (the floor law's provenance rule).
        match floor::check_sequence(
            self.floors,
            &share.scope_root_name,
            verified.sequence,
            floor::Strictness::AtOrAboveFloor,
        )
        .await
        {
            Ok(()) => {}
            Err(GateError::Rejected(rejection)) => {
                report_refusal(events, share, &rejection);
                return None;
            }
            Err(GateError::Seam(_)) => return None,
        }
        let candidate =
            match assemble_candidate(self.gateway, self.http, &name, &record_bytes, None).await {
                Ok(candidate) => candidate,
                Err(GateError::Rejected(rejection)) => {
                    report_refusal(events, share, &rejection);
                    return None;
                }
                Err(GateError::Seam(_)) => return None,
            };
        Some((candidate, SharedScopeFloors { epoch, cut_epoch }))
    }

    /// Open the accepted scope's own folder body, and cache the scope seeds the
    /// legs below its root run on: the read seed every read leg unseals with,
    /// and — under a committed `Write` — the write seed this device's own drain
    /// pass derives each published name and signer from. `Ok(None)` leaves the
    /// render tree as the last pass left it, and so does a gate refusal, which
    /// the caller reports.
    ///
    /// Both seeds come off the record this pass just resolved, never off the
    /// bookmark: a grant the owner has since cut yields no blob at this
    /// device's tag, so the capability lapses with the grant instead of
    /// outliving it at rest.
    ///
    /// Two records may render, and no third. A strictly-newer one adopts through
    /// the gate. One at exactly the durable sequence floor, at or above the
    /// read-epoch floor, is the record this vault already adopted, so re-rendering
    /// it downgrades nothing — the equal-floor recovery the owner's own root leg
    /// makes, and sound for the same reason: the gate authenticates the grant
    /// section under the contact-anchored owner identity before any floor stage
    /// runs.
    async fn open<'s>(
        &self,
        candidate: &Candidate,
        share: &'s ReceivedShare,
        keys: BlobKeys<'_>,
        epoch_floor: u64,
        permission: Permission,
        render: &ScopeRender<'_>,
    ) -> Result<Option<Opened<'s>>, GateRejection> {
        let BlobKeys {
            contact,
            enc_secret,
        } = keys;
        // A scope root is the node its own scope is named for, and the bookmark
        // opens under that id. The reader-scope bind is stage 6's, so state it
        // here too: the equal-floor arm below unseals without reaching stage 6.
        if candidate.envelope.id != share.scope_id || candidate.envelope.scope != share.scope_id {
            return Err(GateRejection {
                stage: GateStage::Unseal,
                reason: RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
            });
        }
        // The scope root is a node id like any other, and a sharer authors it.
        // One this vault's own tree holds would be renamed here and pruned to the
        // children this body names. A root another *sharer's* subtree holds is
        // grafted anyway: a foreign body can link any id under its own folders,
        // and refusing on that alone would let one contact deny another contact's
        // share for good.
        if in_own_tree(&render.base.borrow(), NodeId(share.scope_id)) {
            return Ok(None);
        }
        let Some(blob) =
            recipient_blinded_tag(enc_secret, &contact.enc_subkey(), &share.scope_root_name)
                .and_then(|tag| self_locate_signed(&candidate.grant_section.grant_blobs, &tag))
        else {
            return Ok(None);
        };
        let aad = AadContext {
            v: candidate.envelope.v,
            id: candidate.envelope.id,
            scope: candidate.envelope.scope,
            epoch: candidate.envelope.epoch,
            struct_tag: STRUCT_TAG_GRANT_BLOB,
        };
        let grant =
            open_grant_blob(enc_secret, &blob.enc, &aad, &blob.ciphertext).map_err(|e| {
                GateRejection {
                    stage: GateStage::Unseal,
                    reason: RejectionReason::Trust(e),
                }
            })?;
        let node_seed = kdf::node_seed(grant.read_scope_seed(), &candidate.envelope.id);
        let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
        let reader = ReaderContext {
            owner_identity: &contact.identity_pk(),
            scope_id: share.scope_id,
            read_key: &read_key,
            parent_node_seed: None,
            seed_blob: Some(SeedBlob::Grantee {
                enc_secret,
                enc: blob.enc,
                ciphertext: blob.ciphertext.clone(),
                aad,
            }),
        };
        // The seed's stamp is the epoch that entitles it: an adopt names the one
        // it just raised the floor to, and an equal-floor recovery takes the
        // pre-resolve floor, so no record can extend its own seed's residency.
        let body = match adopt(&self.sharer_floors(share), &reader, candidate).await {
            Ok((adopted, _)) => Some((adopted.read_body, adopted.sequence, adopted.epoch)),
            Err(GateError::Rejected(rejection)) => match rejection.reason {
                RejectionReason::SequenceNotNewer { floor, sequence }
                    if sequence == floor && candidate.envelope.epoch >= epoch_floor =>
                {
                    let body = open_read_body(&candidate.envelope, &read_key).map_err(|e| {
                        GateRejection {
                            stage: GateStage::Unseal,
                            reason: RejectionReason::Trust(e),
                        }
                    })?;
                    Some((body, sequence, epoch_floor))
                }
                _ => return Err(rejection),
            },
            Err(GateError::Seam(_)) => None,
        };
        let Some((
            ReadBody::Folder {
                modified_at,
                children,
                ..
            },
            sequence,
            epoch,
        )) = body
        else {
            return Ok(None);
        };
        deposit_seed(
            render.read_seeds,
            share.scope_id,
            Zeroizing::new(*grant.read_scope_seed()),
            Some(epoch),
        );
        if !is_own_scope(
            render.own_root,
            &render.own_descendants.borrow(),
            &share.scope_id,
        ) {
            match (permission == Permission::Write)
                .then(|| grant.write_scope_seed())
                .flatten()
            {
                // Stamped with the read seed's epoch, which is the epoch the
                // blob that carried both belongs to: an owner's rotation raises
                // the read-epoch floor past it and evicts the write capability
                // with the read one.
                Some(write_scope_seed) => deposit_write_seed(
                    render.write_seeds,
                    share.scope_id,
                    Zeroizing::new(*write_scope_seed),
                    scope_name(&share.scope_root_name).ok().as_ref(),
                    Some(epoch),
                ),
                // The blob this pass opened is the whole of the capability, so
                // an owner that re-sealed the grant down to read cuts the write
                // plane on this pass rather than at the next floor rise.
                None => {
                    render.write_seeds.borrow_mut().remove(&share.scope_id);
                }
            }
        }
        Ok(Some(Opened {
            share,
            children,
            sequence,
            modified_at,
        }))
    }
}

/// Whether the owner-signed commitment names the tag `enc_secret` derives and
/// the blob there opens under it. A link holder reads its personal tag only
/// then, so a blob it cannot open leaves the link as its way in. Not a trust
/// verdict: [`facts_from`] still runs the whole of stage 2 on the path this
/// picks.
fn personal_blob_opens(
    candidate: &Candidate,
    share: &ReceivedShare,
    enc_secret: &X25519Secret,
    sharer_enc_pub: &X25519Public,
) -> bool {
    let section = &candidate.grant_section;
    let Some(tag) = recipient_blinded_tag(enc_secret, sharer_enc_pub, &share.scope_root_name)
    else {
        return false;
    };
    if !section.commitment.entries.iter().any(|e| e.tag == tag) {
        return false;
    }
    let Some(blob) = self_locate_signed(&section.grant_blobs, &tag) else {
        return false;
    };
    let aad = AadContext {
        v: candidate.envelope.v,
        id: candidate.envelope.id,
        scope: candidate.envelope.scope,
        epoch: candidate.envelope.epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    };
    open_grant_blob(enc_secret, &blob.enc, &aad, &blob.ciphertext).is_ok()
}

/// What a resolved scope root supports, as a pure function of the record and the
/// verified contact anchors.
///
/// A commitment [`verify_commitment_in_force`] refuses is not a fresh
/// owner-signed record — a party republishing at that name proves nothing about
/// your grant, so the row renders unresolvable rather than a removal, and the
/// refusal itself is the gate's, which the caller reports.
pub(crate) fn facts_from(
    candidate: &Candidate,
    share: &ReceivedShare,
    my_enc_secret: &X25519Secret,
    sharer_identity: &EcdsaVerifier,
    sharer_enc_pub: &X25519Public,
    floors: SharedScopeFloors,
) -> Result<ResolutionFacts, GateRejection> {
    let scope_root_name = share.scope_root_name.as_slice();
    // The epoch below is measured against `share.scope_id`'s floor, so the
    // record must claim that scope — the binding the adoption gate makes, on a
    // path that reaches no verdict from unsealing.
    if candidate.envelope.scope != share.scope_id {
        return Err(GateRejection {
            stage: GateStage::Unseal,
            reason: RejectionReason::Trust(TrustViolation::SealOpenFailed.into()),
        });
    }
    let section = &candidate.grant_section;
    // The gate's stage 2 entire, so a browse of this row opens exactly the
    // records the row calls granted. A write-only cut republishes at the scope's
    // unchanged read epoch, so the epoch-lag rung below cannot stand in for the
    // cut bar.
    verify_commitment_in_force(sharer_identity, section, scope_root_name, floors.cut_epoch)
        .map_err(|e| GateRejection {
            stage: GateStage::CommitmentVerify,
            reason: RejectionReason::Trust(e),
        })?;
    // The owner-signed commitment is the authority, so a blob at an uncommitted
    // tag is not a grant: it counts as removal, the same verdict the accept flow
    // reaches by refusing an uncommitted tag.
    let blob_present = recipient_blinded_tag(my_enc_secret, sharer_enc_pub, scope_root_name)
        .is_some_and(|tag| {
            section.commitment.entries.iter().any(|e| e.tag == tag)
                && self_locate_signed(&section.grant_blobs, &tag).is_some()
        });
    Ok(ResolutionFacts {
        owner_signed_record: true,
        blob_present,
        record_epoch: candidate.envelope.epoch,
        epoch_floor: floors.epoch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::sync::model::Snapshot;

    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::kdf;
    use cipherbox_core::seal::ChildRef;
    use cipherbox_core::seal::{NodeKind as CoreNodeKind, Permission, PreservedFields};
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};
    use cipherbox_core::suite::secret::SecretBytes;

    use core::cell::Cell;
    use core::pin::pin;
    use core::task::{Context, Waker};
    use std::sync::{Arc, Mutex};

    use crate::content::GatewaySource;
    use crate::facade::MAX_FOLDER_CHILDREN;
    use crate::gate::{CUT_EPOCH_SUFFIX, record_cut_epoch_floor};
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::seams::{FloorRaise, SeamError, SeamResult};
    use crate::testkit::fakes::InMemoryFloorStore;
    use crate::testkit::fakes::{InMemoryRecordStore, InMemoryStagingStore, ScriptedHttp};
    use crate::testkit::requested_cid;
    use cipherbox_core::seal::{Envelope, GrantSection};

    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_POINTER_READ_KEY, OWNER_ROOT_WRITE_SCOPE_SEED,
        OwnerRootFixture, OwnerRootSpec, SeededEntropy, block_on, owner_root_fixture,
        owner_root_pseudonym, reencoded, with_cut_epoch,
    };

    use crate::name::{MAX_NODE_NAME_BYTES, is_emittable};
    use crate::sync::tick::ResolveMode;

    use super::super::accept::{ReceivedShareStoreError, ReceivedSharesList};
    use super::super::ledger::mint_grant_row;
    use super::super::revocation::{ResolutionClass, ResolutionFacts, classify};

    const SCOPE: [u8; 16] = [0x5c; 16];
    /// This vault's own root, which the shared scope is grafted in beside.
    const VAULT_ROOT: [u8; 16] = [0u8; 16];
    const SHARER_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];
    /// A second granting identity, for the scopes one sharer's cut must leave
    /// alone.
    const OTHER_SHARER_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x07; IDENTITY_PUBLIC_LEN];
    fn sharer_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar")
    }

    fn other_sharer_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x71; 32]).expect("valid scalar")
    }

    /// A recipient that is not this device.
    fn someone_else() -> X25519Public {
        X25519Secret::from_scalar([0x55; 32]).public()
    }

    /// The sharer's encryption subkey — the blinded tag's owner-side half.
    fn sharer_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x33; 32])
    }

    /// This device's encryption subkey.
    fn my_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x44; 32])
    }

    fn label_seed() -> SecretBytes {
        kdf::contact_label_seed(&[0x4c; 32])
    }

    fn scope_root_name() -> IpnsName {
        derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE)
    }

    /// The published scope root at the shared scope, committing a grant to each
    /// recipient in `recipients`.
    fn published(sharer: &EcdsaSigner, recipients: &[&X25519Public]) -> OwnerRootFixture {
        let name = scope_root_name();
        let grants = recipients
            .iter()
            .map(|recipient| {
                mint_grant_row(
                    sharer,
                    &sharer_enc(),
                    &OWNER_ROOT_POINTER_READ_KEY,
                    SHARER_IDENTITY_PK,
                    recipient,
                    &SCOPE,
                    name.as_str().as_bytes(),
                    Permission::Read,
                )
                .expect("a contributory recipient key")
            })
            .collect();
        owner_root_fixture(OwnerRootSpec {
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            owner_identity: sharer,
            owner_enc: &sharer_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children: Vec::new(),
            child_scope_index: Vec::new(),
            grants,
            parent_node_seed: None,
            owner_write_blob_epoch: None,
            write_history_link: Vec::new(),
        })
    }

    /// The scope root the owner publishes at a cut: the same set re-signed at
    /// `cut_epoch`, committing `recipients` alone.
    fn cut_at(
        sharer: &EcdsaSigner,
        cut_epoch: u64,
        recipients: &[&X25519Public],
    ) -> OwnerRootFixture {
        with_cut_epoch(published(sharer, recipients), sharer, cut_epoch)
    }

    /// That same root as the candidate a resolve would assemble.
    fn resolved(sharer: &EcdsaSigner, recipients: &[&X25519Public]) -> Candidate {
        let fixture = published(sharer, recipients);
        Candidate {
            name: fixture.name,
            record_bytes: Vec::new(),
            grant_section: fixture.grant_section,
            envelope: fixture.envelope,
        }
    }

    /// The bookmark an accept left behind for the shared scope.
    fn bookmark() -> ReceivedShare {
        ReceivedShare {
            scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
            scope_id: SCOPE,
            sharer_identity_pk: SHARER_IDENTITY_PK,
            display_name: "shared-folder".to_owned(),
            permission: Permission::Read,
            pointer_read_key: SecretBytes::new([0x9a; 32]),
        }
    }

    /// The floors of a device that has adopted this scope at `epoch` and has
    /// seen no cut of it.
    fn floors_at(epoch: u64) -> SharedScopeFloors {
        SharedScopeFloors {
            epoch,
            cut_epoch: 0,
        }
    }

    fn classify_at(candidate: &Candidate, sharer: &EcdsaSigner, floor: u64) -> ResolutionClass {
        classify(&facts_at(candidate, sharer, floor).expect("the record clears stage 2"))
    }

    fn facts_at(
        candidate: &Candidate,
        sharer: &EcdsaSigner,
        floor: u64,
    ) -> Result<ResolutionFacts, GateRejection> {
        facts_from(
            candidate,
            &bookmark(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floors_at(floor),
        )
    }

    /// The stage a refused record's rejection names.
    fn refused_at(facts: Result<ResolutionFacts, GateRejection>) -> GateStage {
        facts.expect_err("the gate refuses the record").stage
    }

    /// Which durable bar a [`FailingFloorRead`] store refuses to answer. Every
    /// other read answers "never raised", and every write fails — a resolve
    /// raises none.
    enum Unreadable {
        /// Every floor, the shape a wholly unavailable host presents.
        Every,
        /// The per-name sequence floor — the replay bar.
        Sequence,
        /// The per-scope cut-epoch floor — the superseded-set bar.
        CutEpoch,
    }

    /// A floor store that fails one read, against a record plane that serves the
    /// shared scope root — so the only thing standing between the resolve and
    /// `Granted` is how the failed read is treated.
    struct FailingFloorRead(Unreadable);

    impl FloorStore for FailingFloorRead {
        async fn epoch_floor(&self, scope_id: &[u8]) -> SeamResult<Option<u64>> {
            match self.0 {
                Unreadable::Every => Err(SeamError::new("floor store unavailable")),
                Unreadable::CutEpoch if scope_id.ends_with(CUT_EPOCH_SUFFIX) => {
                    Err(SeamError::new("cut-epoch floor unavailable"))
                }
                _ => Ok(None),
            }
        }
        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn sequence_floor(&self, _name: &[u8]) -> SeamResult<Option<u64>> {
            match self.0 {
                Unreadable::Every | Unreadable::Sequence => {
                    Err(SeamError::new("sequence floor unavailable"))
                }
                Unreadable::CutEpoch => Ok(None),
            }
        }
        async fn raise_sequence_floor(&self, _name: &[u8], _seq: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn commit_floors(&self, _raises: &[FloorRaise]) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store unavailable"))
        }
    }

    /// A floor store that answers every read "never raised" and fails every
    /// write — the host that can still serve its durable state but can no longer
    /// extend it.
    struct UnwritableFloors;

    impl FloorStore for UnwritableFloors {
        async fn epoch_floor(&self, _scope_id: &[u8]) -> SeamResult<Option<u64>> {
            Ok(None)
        }
        async fn raise_epoch_floor(&self, _scope_id: &[u8], _epoch: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store is full"))
        }
        async fn sequence_floor(&self, _name: &[u8]) -> SeamResult<Option<u64>> {
            Ok(None)
        }
        async fn raise_sequence_floor(&self, _name: &[u8], _seq: u64) -> SeamResult<u64> {
            Err(SeamError::new("floor store is full"))
        }
        async fn commit_floors(&self, _raises: &[FloorRaise]) -> SeamResult<()> {
            Err(SeamError::new("floor store is full"))
        }
        async fn clear(&self) -> SeamResult<()> {
            Err(SeamError::new("floor store is full"))
        }
    }

    /// A floor store holding `cut_epoch` for `sharer`'s [`SCOPE`], with the
    /// read-epoch and sequence bars at the highest value the served root still
    /// passes — so a refusal can only be the cut bar's.
    fn seeded_floors(sharer: [u8; IDENTITY_PUBLIC_LEN], cut_epoch: u64) -> InMemoryFloorStore {
        let floors = InMemoryFloorStore::default();
        block_on(async {
            let scoped = SharerScopedFloorStore::granted_by(
                &floors,
                ContactLabel::of(&label_seed(), &sharer),
            );
            record_cut_epoch_floor(&scoped, &SCOPE, cut_epoch).await?;
            scoped.raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH).await?;
            floors
                .raise_sequence_floor(scope_root_name().as_str().as_bytes(), SERVED_SEQUENCE)
                .await
        })
        .expect("the floor store answers");
        floors
    }

    /// The IPNS sequence [`ServedScopeRoot`] serves its record at.
    const SERVED_SEQUENCE: u64 = 1;

    /// The published scope root and a record plane serving it — everything a
    /// resolve needs except the floor store under test.
    struct ServedScopeRoot {
        fixture: OwnerRootFixture,
        endpoint: EndpointId,
        records: InMemoryRecordStore,
        http: ScriptedHttp,
        gateway: Gateway,
        /// Whether the last resolve reported a trust violation.
        reported: Cell<bool>,
    }

    impl ServedScopeRoot {
        /// The pre-cut set, committing this device.
        fn new(sharer: &EcdsaSigner) -> ServedScopeRoot {
            ServedScopeRoot::serving(published(sharer, &[&my_enc().public()]), SERVED_SEQUENCE)
        }

        fn serving(fixture: OwnerRootFixture, sequence: u64) -> ServedScopeRoot {
            let endpoint = EndpointId::new("e0");
            let records = InMemoryRecordStore::new(vec![endpoint.clone()]);
            let served = ServedScopeRoot {
                fixture,
                endpoint,
                records,
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                    ..Default::default()
                },
                reported: Cell::new(false),
            };
            served.seed(sequence);
            served
        }

        /// Answer the same name with `fixture` at `sequence` from now on — the
        /// republish a surviving write grantee makes.
        fn serve(&mut self, fixture: OwnerRootFixture, sequence: u64) {
            self.fixture = fixture;
            self.seed(sequence);
        }

        fn seed(&self, sequence: u64) {
            self.records.seed_record(
                &self.endpoint,
                self.fixture.name.as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(
                        kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes(),
                    ),
                    format!("/ipfs/{}", self.fixture.head_cid_str).as_bytes(),
                    sequence,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
        }

        fn resolve<F: FloorStore>(&self, floors: &F, sharer: &EcdsaSigner) -> ResolutionClass {
            self.resolve_as(floors, &bookmark(), sharer)
        }

        /// The verdict `share`'s row renders, floor raises and all.
        fn resolve_as<F: FloorStore>(
            &self,
            floors: &F,
            share: &ReceivedShare,
            sharer: &EcdsaSigner,
        ) -> ResolutionClass {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.fixture.head_block.clone(),
            });
            let (events, mut rx) = mpsc::unbounded();
            let class = block_on(
                ReceivedShareStatus {
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors,
                    enc_secret: &my_enc(),
                    contact_label_seed: &label_seed(),
                    list_lock: &ReceivedSharesLock::new(()),
                    mode: ResolveMode::CacheFirst,
                }
                .classified(
                    share,
                    &Contact::from(&ContactCode::create(sharer, sharer_enc().public())),
                    None,
                    &events,
                ),
            )
            .class;
            drop(events);
            self.reported.set(
                core::iter::from_fn(|| rx.try_recv().ok())
                    .any(|event| matches!(event, Event::AttributableAbuse { .. })),
            );
            class
        }
    }

    /// The epoch-lag rung is measured against a floor read from the host. With
    /// no floor the rung can never fire, so a failed read must reach "no
    /// verdict" rather than the `Granted` this very record would otherwise earn.
    #[test]
    fn a_floor_the_host_cannot_read_reaches_no_verdict() {
        let sharer = sharer_signer();
        let served = ServedScopeRoot::new(&sharer);

        // The same resolve against a readable floor store is `Granted` — the
        // record, the commitment and the blob are all in order.
        assert_eq!(
            served.resolve(&InMemoryFloorStore::default(), &sharer),
            ResolutionClass::Granted
        );
        assert_eq!(
            served.resolve(&FailingFloorRead(Unreadable::Every), &sharer),
            ResolutionClass::Unresolvable,
            "an unread floor is availability, never a verdict"
        );
        assert!(!served.reported.get(), "availability accuses nobody");
    }

    /// The replay bar is what keeps a suppressing relay from re-serving the
    /// record that still committed this device and pinning the verdict at
    /// `Granted`, so a sequence floor the host cannot read is absence too.
    #[test]
    fn an_unreadable_sequence_floor_reaches_no_verdict() {
        let sharer = sharer_signer();
        let served = ServedScopeRoot::new(&sharer);
        assert_eq!(
            served.resolve(&FailingFloorRead(Unreadable::Sequence), &sharer),
            ResolutionClass::Unresolvable,
            "an unread replay bar is availability, never a verdict"
        );
        assert!(!served.reported.get(), "availability accuses nobody");
    }

    /// A record below the durable sequence floor is a replay or a rollback: the
    /// row stays unresolvable, and the member hears of it as a trust violation.
    #[test]
    fn a_record_below_the_sequence_floor_is_reported_as_a_trust_violation() {
        let sharer = sharer_signer();
        let floors = InMemoryFloorStore::default();
        block_on(
            floors.raise_sequence_floor(scope_root_name().as_str().as_bytes(), SERVED_SEQUENCE + 1),
        )
        .expect("the floor store answers");
        let served = ServedScopeRoot::new(&sharer);

        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Unresolvable
        );
        assert!(served.reported.get(), "a rollback is a trust verdict");

        let at_floor = InMemoryFloorStore::default();
        block_on(
            at_floor.raise_sequence_floor(scope_root_name().as_str().as_bytes(), SERVED_SEQUENCE),
        )
        .expect("the floor store answers");
        assert_eq!(served.resolve(&at_floor, &sharer), ResolutionClass::Granted);
        assert!(
            !served.reported.get(),
            "the record this device already adopted is no replay"
        );
    }

    /// The control for the two cut tests below: the same seeded read-epoch and
    /// sequence bars, with no cut recorded, still reach `Granted`. Without it a
    /// bar seeded too high would let those tests pass for the wrong reason.
    #[test]
    fn seeded_floors_without_a_cut_leave_the_served_root_granted() {
        let sharer = sharer_signer();
        assert_eq!(
            ServedScopeRoot::new(&sharer).resolve(&seeded_floors(SHARER_IDENTITY_PK, 0), &sharer),
            ResolutionClass::Granted,
            "only the cut bar may refuse the served root"
        );
    }

    /// The cut this device already adopted is read under the granting identity,
    /// at the key the gate reads — so the verdict a `/shared` row renders and
    /// the gate a browse of it passes refuse the same replayed set.
    ///
    /// The other two bars are seeded to their highest passing value: a cut party
    /// that keeps a name's signing key mints a fresh sequence there, and a
    /// write-only cut leaves the read epoch alone, so the cut bar is the only
    /// one that can refuse the replay.
    #[test]
    fn a_cut_this_device_adopted_refuses_the_pre_cut_set_it_would_call_granted() {
        let sharer = sharer_signer();
        let served = ServedScopeRoot::new(&sharer);
        let floors = seeded_floors(SHARER_IDENTITY_PK, 1);

        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Unresolvable,
            "the served root carries the pre-cut set"
        );
        assert!(
            served.reported.get(),
            "a replayed pre-cut set is a trust verdict"
        );
    }

    /// A cut is one sharer's act at one scope. The floor it raises is filed
    /// under the granting identity, so it cannot refuse another sharer's scope
    /// of the same id.
    #[test]
    fn a_cut_under_one_sharer_leaves_another_sharers_scope_of_that_id_granted() {
        let sharer = sharer_signer();
        let served = ServedScopeRoot::new(&sharer);
        let floors = seeded_floors(OTHER_SHARER_IDENTITY_PK, 1);

        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Granted,
            "the cut belongs to an identity this bookmark was not granted by"
        );
    }

    /// The cut bar is a durable read like the other two, so a host that cannot
    /// answer it reaches no verdict rather than the `Granted` a replayed
    /// pre-cut set would otherwise earn.
    #[test]
    fn an_unreadable_cut_epoch_floor_reaches_no_verdict() {
        let sharer = sharer_signer();
        assert_eq!(
            ServedScopeRoot::new(&sharer).resolve(&FailingFloorRead(Unreadable::CutEpoch), &sharer),
            ResolutionClass::Unresolvable,
            "an unread cut bar is availability, never a verdict"
        );
    }

    /// A recipient the owner cut holds no blob in the post-cut set, so it adopts
    /// no post-cut record and the adoption commit never raises its cut-epoch
    /// floor. The classification path is the only place that floor can rise on
    /// that device, and once it has, a surviving write grantee cannot re-grant
    /// the row by republishing the pre-cut root — however new the record it
    /// serves that root in.
    #[test]
    fn a_classified_cut_refuses_the_replayed_pre_cut_set() {
        let sharer = sharer_signer();
        let floors = InMemoryFloorStore::default();
        let mut served =
            ServedScopeRoot::serving(cut_at(&sharer, 1, &[&someone_else()]), SERVED_SEQUENCE);

        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::RevocationSignal,
            "the post-cut set commits this device nowhere"
        );

        served.serve(
            published(&sharer, &[&my_enc().public()]),
            SERVED_SEQUENCE + 1,
        );
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Unresolvable,
            "the row does not return to granted"
        );
        assert_eq!(
            served.resolve(&InMemoryFloorStore::default(), &sharer),
            ResolutionClass::Granted,
            "a device that saw no cut still grants that same replay, so only the
             raised floor refuses it above"
        );
    }

    /// A cut this pass could not record is not a bar this device holds. Rendering
    /// the verdict anyway would leave the next pass measuring a replayed pre-cut
    /// set against a floor that never rose, so the failed raise reaches no
    /// verdict — the treatment an unreadable floor already gets.
    #[test]
    fn a_cut_epoch_floor_this_pass_cannot_raise_reaches_no_verdict() {
        let sharer = sharer_signer();
        let served =
            ServedScopeRoot::serving(cut_at(&sharer, 1, &[&my_enc().public()]), SERVED_SEQUENCE);

        assert_eq!(
            served.resolve(&UnwritableFloors, &sharer),
            ResolutionClass::Unresolvable,
            "an unrecorded cut is availability, never a verdict"
        );
        assert!(!served.reported.get(), "availability accuses nobody");
        assert_eq!(
            served.resolve(&InMemoryFloorStore::default(), &sharer),
            ResolutionClass::Granted,
            "a store that records the cut grants that same record, so only the
             failed raise refuses it above"
        );
    }

    /// The pre-condition on the raise is the whole of gate stage 2, and nothing
    /// less. A commitment an unrelated identity signed states nothing about this
    /// scope root, so the cut epoch it claims may not bar the set the owner
    /// really did sign — otherwise any party that can answer the name locks the
    /// row out for good.
    #[test]
    fn a_commitment_stage_2_refuses_raises_no_floor() {
        let sharer = sharer_signer();
        let impostor = other_sharer_signer();
        let floors = InMemoryFloorStore::default();

        let mut served = ServedScopeRoot::serving(
            cut_at(&impostor, u64::MAX, &[&my_enc().public()]),
            SERVED_SEQUENCE,
        );
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Unresolvable,
            "the bookmarked identity did not sign this commitment"
        );
        assert!(
            served.reported.get(),
            "a forged commitment is a trust verdict"
        );

        served.serve(
            published(&sharer, &[&my_enc().public()]),
            SERVED_SEQUENCE + 1,
        );
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Granted,
            "the refused commitment barred nothing"
        );
    }

    /// A cut is one sharer's act at one scope, and each sharer authors its own
    /// scope id. The floor this raise files is keyed by the granting identity,
    /// so a cut under one sharer cannot refuse another sharer's scope of the
    /// same id.
    #[test]
    fn a_classified_cut_leaves_another_sharers_scope_of_that_id_granted() {
        let cutting = sharer_signer();
        let other = other_sharer_signer();
        let floors = InMemoryFloorStore::default();

        let cut =
            ServedScopeRoot::serving(cut_at(&cutting, 1, &[&someone_else()]), SERVED_SEQUENCE);
        assert_eq!(
            cut.resolve(&floors, &cutting),
            ResolutionClass::RevocationSignal
        );

        let elsewhere = ServedScopeRoot::new(&other);
        assert_eq!(
            elsewhere.resolve_as(
                &floors,
                &ReceivedShare {
                    sharer_identity_pk: OTHER_SHARER_IDENTITY_PK,
                    ..bookmark()
                },
                &other,
            ),
            ResolutionClass::Granted,
            "the cut belongs to an identity this bookmark was not granted by"
        );
    }

    /// The cut-epoch floor is read against commitments alone — never against a
    /// body, a sequence, or a read epoch — so a raise from a record a later gate
    /// stage refuses costs this device nothing it could read. Here the
    /// read-epoch rung refuses the record, and the row keeps rendering the
    /// staleness it rendered before rather than a trust rejection.
    #[test]
    fn a_raise_from_a_record_a_later_stage_refuses_leaves_the_plane_readable() {
        let sharer = sharer_signer();
        let floors = InMemoryFloorStore::default();
        block_on(
            SharerScopedFloorStore::granted_by(
                &floors,
                ContactLabel::of(&label_seed(), &SHARER_IDENTITY_PK),
            )
            .raise_epoch_floor(&SCOPE, OWNER_ROOT_EPOCH + 1),
        )
        .expect("the floor store answers");

        // The owner cut another recipient: the commitment carries the cut, and
        // this device's blob survives in the set.
        let mut served =
            ServedScopeRoot::serving(cut_at(&sharer, 1, &[&my_enc().public()]), SERVED_SEQUENCE);
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::EpochLag,
            "stage 2 passes and the read-epoch rung below it refuses the record"
        );
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::EpochLag,
            "the floor a record raised never refuses that record"
        );

        served.serve(
            published(&sharer, &[&my_enc().public()]),
            SERVED_SEQUENCE + 1,
        );
        assert_eq!(
            served.resolve(&floors, &sharer),
            ResolutionClass::Unresolvable,
            "the raise the refused record made still stands"
        );
    }

    /// The epoch is measured against the bookmarked scope's floor, so a record
    /// claiming another scope is not evidence about this one — it is the scope
    /// transplant the gate refuses.
    #[test]
    fn a_record_that_claims_another_scope_is_refused() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            &ReceivedShare {
                scope_id: [0x11; 16],
                ..bookmark()
            },
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floors_at(OWNER_ROOT_EPOCH),
        );
        assert_eq!(refused_at(facts), GateStage::Unseal);
    }

    #[test]
    fn a_committed_blob_at_your_tag_is_still_granted() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH),
            ResolutionClass::Granted
        );
    }

    /// A set the owner has since cut is a replay: a gate refusal, never read as
    /// a removal.
    #[test]
    fn a_commitment_a_cut_superseded_is_refused() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            &bookmark(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            SharedScopeFloors {
                epoch: OWNER_ROOT_EPOCH,
                cut_epoch: 1,
            },
        );
        assert_eq!(refused_at(facts), GateStage::CommitmentVerify);
    }

    /// The definitive removal: the owner republished the committed set without
    /// you, so a fresh owner-signed record carries no blob at your tag.
    #[test]
    fn a_fresh_owner_signed_record_without_your_blob_is_a_revocation_signal() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&someone_else()]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH),
            ResolutionClass::RevocationSignal
        );
    }

    /// A blob is not authority — the owner-signed commitment is. A record
    /// carrying a blob at your tag that the commitment does not name is a
    /// removal, the verdict the accept flow reaches by refusing that tag.
    #[test]
    fn a_blob_the_commitment_does_not_name_is_a_revocation_signal() {
        let sharer = sharer_signer();
        let someone_else = X25519Secret::from_scalar([0x55; 32]).public();
        let mine = resolved(&sharer, &[&my_enc().public()]);
        // The owner's signed set names only the other recipient; the record
        // still carries this device's blob.
        let mut candidate = resolved(&sharer, &[&someone_else]);
        candidate
            .grant_section
            .grant_blobs
            .extend(mine.grant_section.grant_blobs.iter().cloned());

        let facts = facts_from(
            &candidate,
            &bookmark(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floors_at(OWNER_ROOT_EPOCH),
        )
        .expect("the owner's own commitment still verifies");
        assert!(
            facts.owner_signed_record,
            "the owner's own commitment still verifies"
        );
        assert_eq!(classify(&facts), ResolutionClass::RevocationSignal);
    }

    /// A record another party republished at that name proves nothing about your
    /// grant, so it is refused and never read as a removal.
    #[test]
    fn a_record_the_sharer_did_not_sign_is_refused_never_a_revocation() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let impostor = EcdsaSigner::from_scalar(&[0x71; 32]).expect("valid scalar");

        assert_eq!(
            refused_at(facts_at(&candidate, &impostor, OWNER_ROOT_EPOCH)),
            GateStage::CommitmentVerify,
        );
    }

    /// The same holds for a commitment bound to some other scope root: it is the
    /// sharer's signature over a different name, not a verdict on this one.
    #[test]
    fn a_commitment_bound_to_another_name_is_refused() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            &ReceivedShare {
                scope_root_name: b"some-other-scope-root".to_vec(),
                ..bookmark()
            },
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floors_at(OWNER_ROOT_EPOCH),
        );
        assert_eq!(refused_at(facts), GateStage::CommitmentVerify);
    }

    /// Still committed, but behind the durable read-epoch floor: a sweep-pending
    /// staleness, never a revocation.
    #[test]
    fn a_still_committed_record_below_the_floor_is_epoch_lag() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        assert_eq!(
            classify_at(&candidate, &sharer, OWNER_ROOT_EPOCH + 1),
            ResolutionClass::EpochLag
        );
    }

    // -----------------------------------------------------------------------
    // The render leg: an accepted scope's subtree, in the tree a focus reads.
    // -----------------------------------------------------------------------

    /// A child of the shared scope root, as its read body names one.
    fn shared_child(id: u8, name: &str) -> ChildRef {
        ChildRef {
            id: [id; 16],
            name: name.to_owned(),
            ipns_name: vec![id],
            kind: CoreNodeKind::Folder,
            link_counter: 1,
            unknown: PreservedFields::new(),
        }
    }

    /// The sharer's scope root serving `children`, granting this vault
    /// `permission`. A `Write` row wraps the scope write seed into the blob, as
    /// a real owner's re-seal does.
    fn shared_scope_fixture(children: Vec<ChildRef>, permission: Permission) -> OwnerRootFixture {
        let sharer = sharer_signer();
        let grants = vec![
            mint_grant_row(
                &sharer,
                &sharer_enc(),
                &OWNER_ROOT_POINTER_READ_KEY,
                sharer.verifying_key().to_sec1(),
                &my_enc().public(),
                &SCOPE,
                scope_root_name().as_str().as_bytes(),
                permission,
            )
            .expect("a contributory recipient key"),
        ];
        owner_root_fixture(OwnerRootSpec {
            writer_pseudonym: &owner_root_pseudonym(),
            pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
            owner_identity: &sharer,
            owner_enc: &sharer_enc().public(),
            scope_id: SCOPE,
            root_id: SCOPE,
            children,
            child_scope_index: Vec::new(),
            grants,
            parent_node_seed: None,
            owner_write_blob_epoch: None,
            write_history_link: Vec::new(),
        })
    }

    /// Serve `fixture` at the scope root's name, at `sequence`.
    fn seed_scope_root(records: &InMemoryRecordStore, fixture: &OwnerRootFixture, sequence: u64) {
        records.seed_record(
            &EndpointId::new("e0"),
            fixture.name.as_str(),
            IpnsRecord::create_v2(
                &kdf::ipns_keypair(
                    kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes(),
                ),
                format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
                sequence,
                2_000_000_000,
                "2099-01-01T00:00:00Z",
            )
            .marshal(),
        );
    }

    /// The whole grantee side: the sharer's published scope root serving
    /// `children`, this vault's durable bookmark and contact book, and the render
    /// tree a focus reads.
    struct RenderedScope {
        fixture: OwnerRootFixture,
        records: InMemoryRecordStore,
        http: ScriptedHttp,
        gateway: Gateway,
        floors: InMemoryFloorStore,
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
        base: BaseSnapshot,
        read_seeds: RefCell<ScopeSeeds>,
        write_seeds: RefCell<ScopeSeeds>,
        vault_root: [u8; 16],
        own_descendants: RefCell<BTreeSet<NodeId>>,
        grafted_sharers: RefCell<GraftedSharers>,
        scope_roots: RefCell<BookmarkedScopeRoots>,
        permissions: RefCell<BookmarkedPermissions>,
        claims: RefCell<ClaimRecord>,
        verdicts: RefCell<ReceivedVerdicts>,
        /// The permission the served commitment grants, so a republish keeps it.
        granted: Permission,
        /// Whether the last pass attributed abuse to the sharer.
        reported: Cell<bool>,
        list_lock: ReceivedSharesLock,
    }

    impl RenderedScope {
        fn new(children: Vec<ChildRef>) -> Self {
            Self::rooted_at(children, VAULT_ROOT)
        }

        /// The same world, with this vault's own root anchored at `vault_root`.
        fn rooted_at(children: Vec<ChildRef>, vault_root: [u8; 16]) -> Self {
            Self::granting(children, vault_root, Permission::Read)
        }

        /// The same world under a grant of `permission`.
        fn granting(children: Vec<ChildRef>, vault_root: [u8; 16], permission: Permission) -> Self {
            let fixture = shared_scope_fixture(children, permission);
            let records = InMemoryRecordStore::new(vec![EndpointId::new("e0")]);
            seed_scope_root(&records, &fixture, 1);
            let fx = Self {
                fixture,
                records,
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                    ..Default::default()
                },
                floors: InMemoryFloorStore::default(),
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(9)),
                base: BaseSnapshot::new(Snapshot::new(NodeId(vault_root))),
                read_seeds: RefCell::new(ScopeSeeds::new()),
                write_seeds: RefCell::new(ScopeSeeds::new()),
                vault_root,
                own_descendants: RefCell::new(BTreeSet::new()),
                grafted_sharers: RefCell::new(GraftedSharers::new()),
                scope_roots: RefCell::new(BookmarkedScopeRoots::new()),
                permissions: RefCell::new(BookmarkedPermissions::new()),
                claims: RefCell::new(ClaimRecord::default()),
                verdicts: RefCell::new(ReceivedVerdicts::new()),
                granted: permission,
                reported: Cell::new(false),
                list_lock: ReceivedSharesLock::new(()),
            };
            block_on(
                StagingContactStore::new(&fx.staging, &my_enc(), &fx.entropy)
                    .record(&ContactCode::create(&sharer_signer(), sharer_enc().public()).encode()),
            )
            .expect("the sharer's code imports");
            fx
        }

        /// Bookmark every served scope, as an accept would have.
        fn bookmark(&self) {
            self.bookmark_sharers(&[sharer_signer().verifying_key().to_sec1()]);
        }

        /// The same bookmark, recording `permission` — the accept's snapshot of
        /// what the commitment permitted then.
        fn bookmark_at(&self, permission: Permission) {
            let mut list = ReceivedSharesList::new();
            list.reconcile(ReceivedShare {
                scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
                scope_id: SCOPE,
                sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                display_name: "shared-folder".to_owned(),
                permission,
                pointer_read_key: SecretBytes::new([0x9a; 32]),
            });
            self.persist(&list).expect("the bookmark persists");
        }

        /// The same bookmark, under a label the sharer chose.
        fn bookmark_labelled(&self, display_name: &str) {
            self.try_bookmark_labelled(display_name)
                .expect("the bookmark persists");
        }

        /// The same, reporting whether the durable store took the label.
        fn try_bookmark_labelled(&self, display_name: &str) -> Result<(), ReceivedShareStoreError> {
            let mut list = ReceivedSharesList::new();
            list.reconcile(ReceivedShare {
                scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
                scope_id: SCOPE,
                sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                display_name: display_name.to_owned(),
                permission: Permission::Read,
                pointer_read_key: SecretBytes::new([0x9a; 32]),
            });
            self.persist(&list)
        }

        /// Bookmark the shared scope once per identity in `sharers` — the same
        /// `scopeId` claimed by each, which is what a second sharer minting that
        /// id looks like from here.
        fn bookmark_sharers(&self, sharers: &[[u8; IDENTITY_PUBLIC_LEN]]) {
            let mut list = ReceivedSharesList::new();
            for sharer in sharers {
                list.reconcile(ReceivedShare {
                    scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
                    scope_id: SCOPE,
                    sharer_identity_pk: *sharer,
                    display_name: "shared-folder".to_owned(),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new([0x9a; 32]),
                });
            }
            self.persist(&list).expect("the bookmarks persist");
        }

        fn persist(&self, list: &ReceivedSharesList) -> Result<(), ReceivedShareStoreError> {
            block_on(
                StagingReceivedShareStore::new(&self.staging, &my_enc(), &self.entropy)
                    .persist(list),
            )
        }

        /// Bookmark the shared scope, plus a second accepted scope at `other`
        /// from the same sharer. `other` names a root no record is seeded at, so
        /// it resolves to nothing and only its renderable id matters here.
        fn bookmark_with_extra_scope(&self, other: [u8; 16]) {
            let mut list = ReceivedSharesList::new();
            for (scope, name) in [
                (SCOPE, scope_root_name()),
                (
                    other,
                    derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &other),
                ),
            ] {
                list.reconcile(ReceivedShare {
                    scope_root_name: name.as_str().as_bytes().to_vec(),
                    scope_id: scope,
                    sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                    display_name: "shared-folder".to_owned(),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new([0x9a; 32]),
                });
            }
            self.persist(&list).expect("the bookmarks persist");
        }

        /// Answer the same name with `children` at `sequence` from now on — the
        /// republish the owner makes when it adds a file after the grant.
        fn republish(&mut self, children: Vec<ChildRef>, sequence: u64) {
            self.fixture = shared_scope_fixture(children, self.granted);
            seed_scope_root(&self.records, &self.fixture, sequence);
        }

        /// Answer the same name with a set that commits another recipient
        /// alone — the owner's cut of this vault's own row, with no floor moved.
        fn cut(&mut self, sequence: u64) {
            self.fixture = published(&sharer_signer(), &[&someone_else()]);
            seed_scope_root(&self.records, &self.fixture, sequence);
        }

        /// Re-seal the grant at `permission` and republish — the owner's
        /// downgrade of a share this vault already accepted.
        fn regrant(&mut self, permission: Permission, children: Vec<ChildRef>, sequence: u64) {
            self.granted = permission;
            self.republish(children, sequence);
        }

        /// One poll-cadence received-share pass, with the head block its resolve
        /// fetches served.
        fn pass(&self, at_millis: u64) -> ResolutionClass {
            self.pass_in(at_millis, ResolveMode::CacheFirst)
        }

        /// One `Command::ManualRefresh` pass — the forced, nocache leg.
        fn forced_pass(&self, at_millis: u64) -> ResolutionClass {
            self.pass_in(at_millis, ResolveMode::NoCache)
        }

        fn pass_in(&self, at_millis: u64, mode: ResolveMode) -> ResolutionClass {
            self.pass_over(&self.records, at_millis, mode)
        }

        /// One pass whose records come from `transport`.
        fn pass_over<T: RecordTransport>(
            &self,
            transport: &T,
            at_millis: u64,
            mode: ResolveMode,
        ) -> ResolutionClass {
            let (events, mut rx) = mpsc::unbounded();
            block_on(self.refresh_over(transport, &events, at_millis, mode));
            drop(events);
            self.reported.set(
                core::iter::from_fn(|| rx.try_recv().ok())
                    .any(|event| matches!(event, Event::AttributableAbuse { .. })),
            );
            self.verdicts
                .borrow()
                .get(&(sharer_signer().verifying_key().to_sec1(), SCOPE))
                .map_or(ResolutionClass::Unresolvable, |verdict| verdict.class)
        }

        /// The pass itself, with the head block its resolve fetches served.
        fn refresh_over<'s, T: RecordTransport>(
            &'s self,
            transport: &'s T,
            events: &'s mpsc::UnboundedSender<Event>,
            at_millis: u64,
            mode: ResolveMode,
        ) -> impl Future<Output = ()> + 's {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.fixture.head_block.clone(),
            });
            async move {
                ReceivedShareStatus {
                    transport,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors: &self.floors,
                    enc_secret: &my_enc(),
                    contact_label_seed: &label_seed(),
                    list_lock: &self.list_lock,
                    mode,
                }
                .refresh(
                    &self.staging,
                    &self.entropy,
                    &self.verdicts,
                    &ScopeRender {
                        base: &self.base,
                        read_seeds: &self.read_seeds,
                        write_seeds: &self.write_seeds,
                        own_root: &self.vault_root,
                        own_descendants: &self.own_descendants,
                        grafted_sharers: &self.grafted_sharers,
                        scope_roots: &self.scope_roots,
                        permissions: &self.permissions,
                        claims: &self.claims,
                        events,
                    },
                    UnixMillis(at_millis),
                    &SyncTimingProfile::CI,
                )
                .await;
            }
        }

        /// The names the render tree lists under the shared scope root.
        fn listing(&self) -> Vec<String> {
            self.base
                .borrow()
                .children(NodeId(SCOPE))
                .into_iter()
                .map(|child| child.name().to_owned())
                .collect()
        }
    }

    /// A read grantee reads the live folder, not the listing that was current
    /// when the grant was cut. This leg is the only one that resolves a grafted
    /// scope root, so a forced pass the damper skips leaves the owner's later
    /// file unrendered for as long as the recipient keeps refreshing.
    #[test]
    fn a_forced_pass_renders_a_file_the_owner_added_after_the_grant() {
        let mut fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert_eq!(fx.listing(), vec!["photos".to_owned()]);

        fx.republish(
            vec![
                shared_child(0xa1, "photos"),
                shared_child(0xa2, "after-the-grant"),
            ],
            2,
        );

        assert_eq!(fx.forced_pass(1_000), ResolutionClass::Granted);
        assert_eq!(
            fx.listing(),
            vec!["photos".to_owned(), "after-the-grant".to_owned()],
        );
    }

    /// The poll leg keeps its damper, so a bookmark list does not re-resolve on
    /// every tick of a cadence shorter than the staleness threshold.
    #[test]
    fn a_poll_pass_inside_the_staleness_threshold_carries_its_verdict_forward() {
        let mut fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        fx.republish(
            vec![
                shared_child(0xa1, "photos"),
                shared_child(0xa2, "after-the-grant"),
            ],
            2,
        );

        assert_eq!(fx.pass(1_000), ResolutionClass::Granted);
        assert_eq!(
            fx.listing(),
            vec!["photos".to_owned()],
            "the damped pass re-read nothing",
        );

        assert_eq!(fx.pass(60_000), ResolutionClass::Granted);
        assert_eq!(
            fx.listing(),
            vec!["photos".to_owned(), "after-the-grant".to_owned()],
            "and the pass past the threshold renders the owner's addition",
        );
    }

    /// The gap this leg closes: a member could read a share's standing but never
    /// open it, because nothing grafted the accepted scope into the tree a focus
    /// resolves against.
    #[test]
    fn an_accepted_scope_root_and_its_children_reach_the_render_tree() {
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            shared_child(0xa2, "notes"),
        ]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        let base = fx.base.borrow();
        let root = base
            .node(NodeId(SCOPE))
            .expect("the accepted scope root is a node a focus can name");
        assert_eq!(root.kind, NodeKind::Folder);
        assert_eq!(
            root.name(),
            "shared-folder",
            "the pointer's label is the only name a browse can show"
        );
        drop(base);
        assert_eq!(fx.listing(), vec!["photos".to_owned(), "notes".to_owned()]);
    }

    /// The read scope seed the leg below the root needs is recovered from the
    /// grant blob, not persisted — so it must land in the per-scope cache the
    /// focus leg reads.
    #[test]
    fn an_accepted_scope_caches_the_read_seed_its_subtree_is_read_with() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert!(
            fx.read_seeds.borrow().contains_key(&SCOPE),
            "the subtree below the root has read material to resolve with"
        );
        assert!(
            fx.write_seeds.borrow().is_empty(),
            "and a read grant leaves no write material behind"
        );
    }

    /// A write grantee authors under the scope's own write plane, so the focus
    /// leg has to leave the write seed where that device's own drain pass reads
    /// it. The seed rides the same grant blob as the read seed.
    #[test]
    fn a_write_granted_scope_caches_the_write_seed_its_pass_publishes_under() {
        let fx = RenderedScope::granting(
            vec![shared_child(0xa1, "photos")],
            VAULT_ROOT,
            Permission::Write,
        );
        fx.bookmark_at(Permission::Write);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert!(
            fx.write_seeds.borrow().contains_key(&SCOPE),
            "the grafted scope has write material to publish under"
        );
    }

    /// The committed permission is the owner's word and the bookmark's is only
    /// the accept's snapshot of it. A bookmark that claims write against a
    /// commitment that grants read must leave no write material.
    #[test]
    fn a_bookmark_claiming_write_over_a_read_commitment_caches_no_write_seed() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_at(Permission::Write);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert!(
            fx.write_seeds.borrow().is_empty(),
            "the commitment decides, not the bookmark"
        );
    }

    /// The owner cuts a write grant by re-sealing the blob down to read, which
    /// need not move any floor. The cached write seed is the whole of the
    /// capability, so the pass that reads the smaller blob has to drop it.
    #[test]
    fn an_owner_downgrade_to_read_drops_the_cached_write_seed() {
        let mut fx = RenderedScope::granting(
            vec![shared_child(0xa1, "photos")],
            VAULT_ROOT,
            Permission::Write,
        );
        fx.bookmark_at(Permission::Write);
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(fx.write_seeds.borrow().contains_key(&SCOPE));

        fx.regrant(Permission::Read, vec![shared_child(0xa1, "photos")], 2);

        assert_eq!(fx.forced_pass(1_000), ResolutionClass::Granted);
        assert!(
            fx.write_seeds.borrow().is_empty(),
            "the write plane closes on the pass that reads the cut, not at the next floor rise"
        );
    }

    /// A cut need move no floor, so the eviction pass that measures a grafted
    /// seed against the granting identity's read-epoch floor never reaches this
    /// one. The revoked row must therefore lose both cached seeds and its
    /// permission on the pass that reads the cut, or the next tick builds a
    /// write pass out of state the owner has withdrawn.
    #[test]
    fn a_revoked_share_loses_the_cached_capability_on_the_pass_that_reads_the_cut() {
        let mut fx = RenderedScope::granting(
            vec![shared_child(0xa1, "photos")],
            VAULT_ROOT,
            Permission::Write,
        );
        fx.bookmark_at(Permission::Write);
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(fx.write_seeds.borrow().contains_key(&SCOPE));

        fx.cut(2);

        assert_eq!(fx.forced_pass(1_000), ResolutionClass::RevocationSignal);
        assert!(
            fx.read_seeds.borrow().is_empty(),
            "the capability lapses with the grant rather than outliving it"
        );
        assert!(fx.write_seeds.borrow().is_empty(), "the write plane too");
        assert_eq!(
            fx.permissions.borrow().get(&SCOPE),
            Some(&Permission::Read),
            "and the host gates no write affordance on a revoked row"
        );
    }

    /// A scope no pass may render reaches no grant blob, so the deposit's own
    /// removal arm never runs on it. The cached write seed follows the live
    /// permission on every arm instead, or a scope two sharers contest keeps a
    /// write capability this pass never re-established.
    #[test]
    fn a_scope_the_pass_never_opens_loses_a_write_seed_no_permission_holds() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_sharers(&[
            sharer_signer().verifying_key().to_sec1(),
            OTHER_SHARER_IDENTITY_PK,
        ]);
        deposit_seed(&fx.write_seeds, SCOPE, Zeroizing::new([0x33; 32]), Some(0));

        fx.pass(0);

        assert!(fx.write_seeds.borrow().is_empty());
    }

    /// The sharer authors the `scopeId` it bookmarks under, so a revocation on
    /// a scope this vault owns is a stripped row of the sharer's own set and
    /// says nothing about this vault's material. Clearing on it would let any
    /// contact cut this vault off its own plane.
    #[test]
    fn a_revocation_over_an_own_scope_id_clears_no_own_material() {
        let mut fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        fx.own_descendants.borrow_mut().insert(NodeId(SCOPE));
        for cell in [&fx.read_seeds, &fx.write_seeds] {
            deposit_seed(cell, SCOPE, Zeroizing::new([0x33; 32]), Some(0));
        }

        fx.cut(2);

        assert_eq!(fx.forced_pass(1_000), ResolutionClass::RevocationSignal);
        assert!(fx.read_seeds.borrow().contains_key(&SCOPE));
        assert!(fx.write_seeds.borrow().contains_key(&SCOPE));
    }

    /// A sharer authors its own `scopeId`, so one may name a scope this vault
    /// already owns. The write-seed cell is keyed by that id alone, and taking
    /// the deposit would hand this vault's own pass a key the sharer holds.
    #[test]
    fn a_write_grant_over_an_own_scope_id_is_refused_the_deposit() {
        let fx = RenderedScope::granting(
            vec![shared_child(0xa1, "photos")],
            VAULT_ROOT,
            Permission::Write,
        );
        fx.bookmark_at(Permission::Write);
        fx.own_descendants.borrow_mut().insert(NodeId(SCOPE));

        fx.pass(0);

        assert!(
            fx.write_seeds.borrow().is_empty(),
            "an own scope's write plane is never a sharer's to supply"
        );
    }

    /// A host refuses a write at the gesture on the permission the accept
    /// recorded, so the pass has to leave it where a folder read can find it.
    #[test]
    fn an_accepted_scope_records_the_permission_it_was_granted_under() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();

        fx.pass(0);

        assert_eq!(
            fx.permissions.borrow().get(&SCOPE).copied(),
            Some(Permission::Read)
        );
    }

    /// A downgrade republishes the demoted set and rotates the write plane
    /// alone; it delivers no fresh pointer, so the bookmark keeps the permission
    /// the accept recorded. The permission a host gates on is the owner's live
    /// commitment, never the bookmark's superseded copy of it.
    #[test]
    fn a_downgraded_commitment_supersedes_the_permission_the_bookmark_kept() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_at(Permission::Write);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(
            fx.permissions.borrow().get(&SCOPE).copied(),
            Some(Permission::Read),
            "the served commitment demoted this recipient"
        );
    }

    /// The damper leaves most scopes unresolved on most passes. A permission the
    /// live commitment already superseded must not return with the bookmark's
    /// copy the moment a pass skips the scope.
    #[test]
    fn a_pass_that_re_resolves_nothing_keeps_the_superseded_permission() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_at(Permission::Write);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        // Too soon for the damper, so the pass carries the last verdict forward.
        fx.pass(1);

        assert_eq!(
            fx.permissions.borrow().get(&SCOPE).copied(),
            Some(Permission::Read)
        );
    }

    /// A scope no accept ever bookmarked is not this vault's to render, however
    /// resolvable its record is.
    #[test]
    fn a_scope_the_accept_never_reached_renders_nothing() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);

        fx.pass(0);

        assert!(
            fx.base.borrow().node(NodeId(SCOPE)).is_none(),
            "an unbookmarked scope is no part of the tree"
        );
        assert!(fx.read_seeds.borrow().is_empty());
    }

    /// `scopeId` is the sharer's to author and every vault anchors its own root
    /// at the same id, so a bookmark that names this vault's anchor must render
    /// nothing — it would otherwise rename the vault root and unlink every child
    /// the sharer's body does not list.
    #[test]
    fn a_bookmark_at_this_vaults_own_root_scope_grafts_nothing() {
        let fx = RenderedScope::rooted_at(vec![shared_child(0xa1, "photos")], SCOPE);
        fx.base.borrow_mut().upsert_node(NodeMeta::new(
            NodeId([0x11; 16]),
            "mine",
            NodeKind::Folder,
        ));
        fx.base
            .borrow_mut()
            .link_next(NodeId(SCOPE), NodeId([0x11; 16]));
        fx.bookmark();

        fx.pass(0);

        assert_eq!(
            fx.listing(),
            vec!["mine".to_owned()],
            "this vault's own tree stands"
        );
        assert!(
            fx.read_seeds.borrow().is_empty(),
            "and its seed is untouched"
        );
    }

    /// A sharer names their own children. An id this vault already owns is not
    /// one of them, so a foreign body cannot relink a node out of the vault and
    /// under the shared root.
    #[test]
    fn a_child_id_this_vault_already_owns_is_not_grafted() {
        let mine = [0x11; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: mine,
                name: "stolen".to_owned(),
                ipns_name: vec![0x11],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        fx.base
            .borrow_mut()
            .upsert_node(NodeMeta::new(NodeId(mine), "mine", NodeKind::Folder));
        fx.base
            .borrow_mut()
            .link_next(NodeId(VAULT_ROOT), NodeId(mine));
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(base.parent_of(NodeId(mine)), Some(NodeId(VAULT_ROOT)));
        assert_eq!(
            base.node(NodeId(mine)).expect("still held").name(),
            "mine",
            "and the sharer could not rename it either"
        );
    }

    /// `project_folder` never unlinks a child's old parent, so a child id this
    /// sharer does not own would leave the node under two parents, and the
    /// higher `link_counter` would hand it to the sharer. Another accepted
    /// scope's root is such an id: it is parentless, so the vault-root filter
    /// alone lets it through.
    #[test]
    fn another_accepted_scopes_root_is_not_grafted_as_a_child() {
        let other = [0x77; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: other,
                name: "stolen-scope".to_owned(),
                ipns_name: vec![0x77],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        fx.base
            .borrow_mut()
            .upsert_node(NodeMeta::new(NodeId(other), "theirs", NodeKind::Folder));
        fx.bookmark_with_extra_scope(other);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(
            base.parent_of(NodeId(other)),
            None,
            "the other scope root stays parentless"
        );
        assert_eq!(
            base.node(NodeId(other)).expect("still held").name(),
            "theirs",
            "and this sharer could not rename it"
        );
    }

    /// The same rule one level down: a node already linked below another
    /// accepted scope belongs to that sharer's tree, not to this one.
    #[test]
    fn a_node_inside_another_accepted_scope_is_not_grafted_as_a_child() {
        let other = [0x77; 16];
        let theirs = [0x78; 16];
        let fx = RenderedScope::new(vec![
            shared_child(0xa1, "photos"),
            ChildRef {
                id: theirs,
                name: "stolen-node".to_owned(),
                ipns_name: vec![0x78],
                kind: CoreNodeKind::Folder,
                link_counter: 9,
                unknown: PreservedFields::new(),
            },
        ]);
        {
            let mut base = fx.base.borrow_mut();
            base.upsert_node(NodeMeta::new(NodeId(other), "theirs", NodeKind::Folder));
            base.upsert_node(NodeMeta::new(NodeId(theirs), "their-doc", NodeKind::Folder));
            base.link_next(NodeId(other), NodeId(theirs));
        }
        fx.bookmark_with_extra_scope(other);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        let base = fx.base.borrow();
        assert_eq!(
            base.parent_of(NodeId(theirs)),
            Some(NodeId(other)),
            "the node stays under the sharer that owns it"
        );
        assert_eq!(
            base.node(NodeId(theirs)).expect("still held").name(),
            "their-doc",
            "and this sharer could not rename it"
        );
    }

    /// A browse addresses a scope by its id alone, but the sharer authors that
    /// id, so two sharers can each claim one. Neither subtree may then render:
    /// an open on that id could only guess which sharer it meant.
    #[test]
    fn a_scope_id_two_sharers_claim_renders_for_neither() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark_sharers(&[
            sharer_signer().verifying_key().to_sec1(),
            SHARER_IDENTITY_PK,
        ]);

        fx.pass(0);

        assert!(
            fx.base.borrow().node(NodeId(SCOPE)).is_none(),
            "the contested id is no part of the tree"
        );
        assert!(
            fx.read_seeds.borrow().is_empty(),
            "and no sharer's seed is cached under it"
        );
        assert!(
            fx.grafted_sharers.borrow().is_empty(),
            "and no floor namespace answers for it either"
        );
    }

    /// The leg below a grafted root reads that root's epoch floors under the
    /// identity that granted it, so the pass that grafts must record who did.
    #[test]
    fn a_grafted_scope_records_the_identity_that_granted_it() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(
            fx.grafted_sharers.borrow().get(&SCOPE).copied(),
            Some(sharer_signer().verifying_key().to_sec1())
        );
    }

    /// A scope root is a node id like any other, and the sharer authors it. A
    /// body whose root names a node this vault already holds would rename that
    /// node and prune it to the children the body lists.
    #[test]
    fn a_scope_root_at_a_node_this_vault_owns_grafts_nothing() {
        let kept = [0x11; 16];
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        {
            let mut base = fx.base.borrow_mut();
            base.upsert_node(NodeMeta::new(NodeId(SCOPE), "mine", NodeKind::Folder));
            base.link_next(NodeId(VAULT_ROOT), NodeId(SCOPE));
            base.upsert_node(NodeMeta::new(NodeId(kept), "keep", NodeKind::Folder));
            base.link_next(NodeId(SCOPE), NodeId(kept));
        }
        fx.bookmark();

        fx.pass(0);

        assert_eq!(
            fx.listing(),
            vec!["keep".to_owned()],
            "this vault's own subtree stands"
        );
        assert_eq!(
            fx.base
                .borrow()
                .node(NodeId(SCOPE))
                .expect("still held")
                .name(),
            "mine",
            "and the sharer could not rename it"
        );
        assert!(fx.read_seeds.borrow().is_empty());
    }

    /// The other side of that guard. A foreign body can link any id under its
    /// own folders, so a scope root another sharer's subtree already lists must
    /// still graft: a refusal on that alone gives one contact a channel to deny
    /// another contact's share.
    #[test]
    fn a_scope_root_another_shared_subtree_holds_still_grafts() {
        let other = [0x77; 16];
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        {
            let mut base = fx.base.borrow_mut();
            base.upsert_node(NodeMeta::new(NodeId(other), "theirs", NodeKind::Folder));
            base.upsert_node(NodeMeta::new(NodeId(SCOPE), "claimed", NodeKind::Folder));
            base.link_next(NodeId(other), NodeId(SCOPE));
        }
        fx.bookmark_with_extra_scope(other);

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        assert!(
            fx.grafted_sharers.borrow().contains_key(&SCOPE),
            "and the floor namespace answers for it"
        );
    }

    /// The dangerous shape is the transition, not the fresh state. A scope that
    /// already grafted, and that a second bookmark then contests, must lose its
    /// floor namespace with the authority it lost — the leg below it refuses
    /// rather than falling back to this vault's own plane.
    #[test]
    fn a_scope_contested_after_it_grafted_leaves_the_floor_map() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(fx.grafted_sharers.borrow().contains_key(&SCOPE));

        fx.bookmark_sharers(&[
            sharer_signer().verifying_key().to_sec1(),
            SHARER_IDENTITY_PK,
        ]);
        fx.pass(60_000);

        assert!(
            fx.grafted_sharers.borrow().is_empty(),
            "no identity answers for a contested id"
        );
    }

    // -----------------------------------------------------------------------
    // The per-node claim: which scope renders an id both bodies name.
    // -----------------------------------------------------------------------

    /// The id both bodies name in the tests below.
    const CONTESTED_NODE: [u8; 16] = [0xcc; 16];

    /// Two sharers, each with an accepted scope of its own, in one render tree.
    /// The pair is ordered the way the bookmark list is: by sharer identity,
    /// which the sharer authors and can grind.
    struct TwoSharers {
        sharers: [EcdsaSigner; 2],
        encs: [X25519Secret; 2],
        scopes: [[u8; 16]; 2],
        records: InMemoryRecordStore,
        endpoint: EndpointId,
        blocks: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
        http: ScriptedHttp,
        gateway: Gateway,
        floors: InMemoryFloorStore,
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
        base: BaseSnapshot,
        read_seeds: RefCell<ScopeSeeds>,
        write_seeds: RefCell<ScopeSeeds>,
        own_descendants: RefCell<BTreeSet<NodeId>>,
        grafted_sharers: RefCell<GraftedSharers>,
        scope_roots: RefCell<BookmarkedScopeRoots>,
        permissions: RefCell<BookmarkedPermissions>,
        claims: RefCell<ClaimRecord>,
        verdicts: RefCell<ReceivedVerdicts>,
    }

    impl TwoSharers {
        fn new() -> Self {
            let mut parties = [
                (
                    EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar"),
                    X25519Secret::from_scalar([0x33; 32]),
                    SCOPE,
                ),
                (
                    EcdsaSigner::from_scalar(&[0x51; 32]).expect("valid scalar"),
                    X25519Secret::from_scalar([0x53; 32]),
                    [0x6d; 16],
                ),
            ];
            parties.sort_by_key(|(signer, _, _)| signer.verifying_key().to_sec1());
            let [
                (first, first_enc, first_scope),
                (second, second_enc, second_scope),
            ] = parties;
            let blocks: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::default();
            let served = Arc::clone(&blocks);
            let endpoint = EndpointId::new("e0");
            let fx = Self {
                sharers: [first, second],
                encs: [first_enc, second_enc],
                scopes: [first_scope, second_scope],
                records: InMemoryRecordStore::new(vec![endpoint.clone()]),
                endpoint,
                blocks,
                http: ScriptedHttp::with_route(move |request| {
                    let blocks = served.lock().expect("lock");
                    let body = blocks.get(&requested_cid(&request.url))?.clone();
                    Some(Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body,
                    }))
                }),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                    ..Default::default()
                },
                floors: InMemoryFloorStore::default(),
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(9)),
                base: BaseSnapshot::new(Snapshot::new(NodeId(VAULT_ROOT))),
                read_seeds: RefCell::new(ScopeSeeds::new()),
                write_seeds: RefCell::new(ScopeSeeds::new()),
                own_descendants: RefCell::new(BTreeSet::new()),
                grafted_sharers: RefCell::new(GraftedSharers::new()),
                scope_roots: RefCell::new(BookmarkedScopeRoots::new()),
                permissions: RefCell::new(BookmarkedPermissions::new()),
                claims: RefCell::new(ClaimRecord::default()),
                verdicts: RefCell::new(ReceivedVerdicts::new()),
            };
            let mine = my_enc();
            let contacts = StagingContactStore::new(&fx.staging, &mine, &fx.entropy);
            let mut bookmarks = ReceivedSharesList::new();
            for which in 0..2 {
                block_on(contacts.record(
                    &ContactCode::create(&fx.sharers[which], fx.encs[which].public()).encode(),
                ))
                .expect("the sharer's code imports");
                bookmarks.reconcile(ReceivedShare {
                    scope_root_name: fx.scope_name(which).as_str().as_bytes().to_vec(),
                    scope_id: fx.scopes[which],
                    sharer_identity_pk: fx.sharers[which].verifying_key().to_sec1(),
                    display_name: format!("share-{which}"),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new([0x9a; 32]),
                });
            }
            block_on(
                StagingReceivedShareStore::new(&fx.staging, &my_enc(), &fx.entropy)
                    .persist(&bookmarks),
            )
            .expect("the bookmarks persist");
            fx
        }

        fn scope_name(&self, which: usize) -> IpnsName {
            derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &self.scopes[which])
        }

        /// Publish `which` sharer's scope root at `sequence`, serving `children`.
        fn publish(&self, which: usize, children: Vec<ChildRef>, sequence: u64) {
            let scope = self.scopes[which];
            let name = self.scope_name(which);
            let grants = vec![
                mint_grant_row(
                    &self.sharers[which],
                    &self.encs[which],
                    &OWNER_ROOT_POINTER_READ_KEY,
                    self.sharers[which].verifying_key().to_sec1(),
                    &my_enc().public(),
                    &scope,
                    name.as_str().as_bytes(),
                    Permission::Read,
                )
                .expect("a contributory recipient key"),
            ];
            let fixture = owner_root_fixture(OwnerRootSpec {
                writer_pseudonym: &owner_root_pseudonym(),
                pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
                owner_identity: &self.sharers[which],
                owner_enc: &self.encs[which].public(),
                scope_id: scope,
                root_id: scope,
                children,
                child_scope_index: Vec::new(),
                grants,
                parent_node_seed: None,
                owner_write_blob_epoch: None,
                write_history_link: Vec::new(),
            });
            self.blocks
                .lock()
                .expect("lock")
                .insert(fixture.head_cid_str.clone(), fixture.head_block.clone());
            self.records.seed_record(
                &self.endpoint,
                name.as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(
                        kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &scope).as_bytes(),
                    ),
                    format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
                    sequence,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
        }

        /// Leave `which` sharer's name serving bytes no verify accepts, so this
        /// pass reaches no body for it.
        fn unreachable(&self, which: usize) {
            self.records
                .seed_record(&self.endpoint, self.scope_name(which).as_str(), Vec::new());
        }

        fn pass(&self, at_millis: u64) {
            let (events, _rx) = mpsc::unbounded();
            block_on(
                ReceivedShareStatus {
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors: &self.floors,
                    enc_secret: &my_enc(),
                    contact_label_seed: &label_seed(),
                    list_lock: &ReceivedSharesLock::new(()),
                    mode: ResolveMode::CacheFirst,
                }
                .refresh(
                    &self.staging,
                    &self.entropy,
                    &self.verdicts,
                    &ScopeRender {
                        base: &self.base,
                        read_seeds: &self.read_seeds,
                        write_seeds: &self.write_seeds,
                        own_root: &VAULT_ROOT,
                        own_descendants: &self.own_descendants,
                        grafted_sharers: &self.grafted_sharers,
                        scope_roots: &self.scope_roots,
                        permissions: &self.permissions,
                        claims: &self.claims,
                        events: &events,
                    },
                    UnixMillis(at_millis),
                    &SyncTimingProfile::CI,
                ),
            );
        }

        /// The names the render tree lists under `which` sharer's scope root.
        fn listing(&self, which: usize) -> Vec<String> {
            self.base
                .borrow()
                .children(NodeId(self.scopes[which]))
                .into_iter()
                .map(|child| child.name().to_owned())
                .collect()
        }

        fn holds_contested(&self) -> bool {
            self.base.borrow().contains(NodeId(CONTESTED_NODE))
        }

        /// Record what a folder body below `which` sharer's root names, the way
        /// the focus window's folder leg does ([`ClaimRecord::record`]).
        fn record_folder_body(&self, which: usize, folder: [u8; 16], children: &[ChildRef]) {
            self.claims
                .borrow_mut()
                .record(self.scopes[which], folder, children)
                .expect("the body is within the bound");
        }
    }

    /// The folder below the honest sharer's root, whose body names
    /// [`CONTESTED_NODE`].
    const DEEP_FOLDER: [u8; 16] = [0xf1; 16];

    /// A hostile root body that reaches for a node deep in an honest sharer's
    /// subtree gets it under neither plane. The order does not matter: the
    /// honest folder leg refreshes only while the focus window holds it, so the
    /// hostile root body reaches the snapshot first in almost every case.
    #[test]
    fn a_root_body_that_names_a_deep_node_of_another_scope_renders_it_under_neither() {
        for honest_first in [true, false] {
            let fx = TwoSharers::new();
            fx.publish(0, vec![shared_child(0xa1, "own")], 1);
            fx.publish(1, vec![shared_child(0xf1, "a-folder")], 1);
            fx.pass(0);

            fx.publish(
                0,
                vec![shared_child(0xa1, "own"), shared_child(0xcc, "deep-steal")],
                2,
            );
            let honest = [shared_child(0xcc, "mine")];
            if honest_first {
                fx.record_folder_body(1, DEEP_FOLDER, &honest);
                fx.pass(60_000);
            } else {
                fx.pass(60_000);
                assert!(fx.holds_contested(), "the hostile body was alone on the id");
                fx.record_folder_body(1, DEEP_FOLDER, &honest);
                fx.pass(120_000);
            }

            assert_eq!(fx.listing(0), vec!["own".to_owned()]);
            assert!(!fx.holds_contested());
        }
    }

    /// The record is keyed per body, so a fresh root body replaces what the root
    /// named and nothing else. Keyed per scope, the pass that re-opens the
    /// honest root would erase the folder leg's claim and hand the id over.
    #[test]
    fn a_root_body_replace_keeps_a_folder_bodys_ids() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xa1, "own")], 1);
        fx.publish(1, vec![shared_child(0xf1, "a-folder")], 1);
        fx.pass(0);
        fx.record_folder_body(1, DEEP_FOLDER, &[shared_child(0xcc, "mine")]);

        fx.publish(
            1,
            vec![shared_child(0xf1, "a-folder"), shared_child(0xa2, "more")],
            2,
        );
        fx.publish(
            0,
            vec![shared_child(0xa1, "own"), shared_child(0xcc, "deep-steal")],
            2,
        );
        fx.pass(60_000);

        assert_eq!(fx.listing(0), vec!["own".to_owned()]);
        assert!(!fx.holds_contested());
    }

    /// A body the scope's own fresh root body stops naming loses its claim in
    /// that pass. The render tree drops the folder in the same pass but after
    /// the prune, so a prune keyed on the tree would hold the contest against a
    /// scope that is already alone on the id for one pass more.
    #[test]
    fn a_folder_the_scope_stops_naming_loses_its_claim_in_that_pass() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xa1, "own")], 1);
        fx.publish(1, vec![shared_child(0xf1, "a-folder")], 1);
        fx.pass(0);
        fx.record_folder_body(1, DEEP_FOLDER, &[shared_child(0xcc, "mine")]);

        // The honest root stops naming the folder, so the folder departs.
        fx.publish(1, vec![shared_child(0xa2, "other")], 2);
        fx.publish(
            0,
            vec![shared_child(0xa1, "own"), shared_child(0xcc, "now-free")],
            2,
        );
        fx.pass(60_000);

        assert!(
            !fx.base.borrow().contains(NodeId(DEEP_FOLDER)),
            "the folder left the tree"
        );
        assert_eq!(
            fx.listing(0),
            vec!["own".to_owned(), "now-free".to_owned()],
            "the body its own scope dropped contests nothing"
        );
    }

    /// A folder the contest departs keeps the claim its body made. Freeing those
    /// ids would hand them to the scope that raised the contest, and the honest
    /// scope could not take them back: the focus window re-reads only a folder
    /// the render tree still holds.
    #[test]
    fn a_contested_folder_keeps_the_claim_its_body_made() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xa1, "own")], 1);
        fx.publish(1, vec![shared_child(0xf1, "a-folder")], 1);
        fx.pass(0);
        fx.record_folder_body(1, DEEP_FOLDER, &[shared_child(0xcc, "mine")]);

        // The hostile root names the honest folder itself, which departs it.
        fx.publish(
            0,
            vec![shared_child(0xa1, "own"), shared_child(0xf1, "reach")],
            2,
        );
        fx.pass(60_000);
        assert!(
            !fx.base.borrow().contains(NodeId(DEEP_FOLDER)),
            "the contested folder left the tree"
        );

        // Now the hostile root reaches for the id that folder's body named.
        fx.publish(
            0,
            vec![
                shared_child(0xa1, "own"),
                shared_child(0xf1, "reach"),
                shared_child(0xcc, "steal"),
            ],
            3,
        );
        fx.pass(120_000);

        assert_eq!(
            fx.listing(0),
            vec!["own".to_owned()],
            "the departed folder still claims what its body named"
        );
        assert!(!fx.holds_contested());
    }

    // -----------------------------------------------------------------------
    // The sharer-authored label, held to the node-name law.
    // -----------------------------------------------------------------------

    /// The node-id fallback must itself pass the law it stands in for.
    #[test]
    fn the_grafted_root_fallback_name_is_lawful() {
        let fallback = grafted_root_name("a\u{202E}b", NodeId(SCOPE));

        assert_eq!(*fallback, node_id_label(NodeId(SCOPE)));
        assert_eq!(validate_name(&fallback), Ok(()));
        assert!(is_emittable(&fallback));
    }

    /// A sharer authors the label and it lands in this vault's render tree as a
    /// node name. An unlawful one must not strand the share: the recipient has
    /// to list the graft and remove it through every projection.
    #[test]
    fn a_sharer_label_the_name_law_refuses_grafts_under_the_node_id() {
        for hostile in ["a\u{202E}gnp.exe", "photos/../etc", "NUL", "trailing "] {
            let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
            fx.bookmark_labelled(hostile);

            assert_eq!(fx.pass(0), ResolutionClass::Granted);

            let base = fx.base.borrow();
            let root = base.node(NodeId(SCOPE)).expect("the graft is a node");
            assert_eq!(root.name(), node_id_label(NodeId(SCOPE)), "for {hostile:?}");
            assert!(is_emittable(root.name()));
            drop(base);
            assert_eq!(fx.listing(), vec!["photos".to_owned()], "and it opens");
        }
    }

    /// The one bound: a label the render tree could not carry as a node name is
    /// never stored in the first place.
    #[test]
    fn a_label_past_the_node_name_bound_never_reaches_the_store() {
        let fx = RenderedScope::new(Vec::new());

        assert!(
            fx.try_bookmark_labelled(&"x".repeat(MAX_NODE_NAME_BYTES))
                .is_ok()
        );
        assert!(
            fx.try_bookmark_labelled(&"x".repeat(MAX_NODE_NAME_BYTES + 1))
                .is_err()
        );
    }

    /// A node id both grafted bodies name renders under neither scope. The
    /// sharer authors every id, so the body the pass reaches first must not take
    /// it.
    #[test]
    fn a_node_id_two_grafted_scopes_name_renders_under_neither() {
        let fx = TwoSharers::new();
        fx.publish(
            0,
            vec![
                shared_child(0xa1, "first-own"),
                shared_child(0xcc, "by-first"),
            ],
            1,
        );
        fx.publish(
            1,
            vec![
                shared_child(0xa2, "second-own"),
                shared_child(0xcc, "by-second"),
            ],
            1,
        );

        fx.pass(0);

        assert_eq!(fx.listing(0), vec!["first-own".to_owned()]);
        assert_eq!(fx.listing(1), vec!["second-own".to_owned()]);
        assert!(!fx.holds_contested(), "and no browse opens the id at all");
    }

    /// The bookmark order is sharer-authored: the key leads with the sharer
    /// identity, and a contact can grind one that sorts first. The side that
    /// already renders the id therefore loses it to the contest whichever side
    /// that is.
    #[test]
    fn the_bookmark_order_does_not_decide_a_contested_node() {
        for (holder, contester) in [(0, 1), (1, 0)] {
            let fx = TwoSharers::new();
            fx.publish(holder, vec![shared_child(0xcc, "held")], 1);
            fx.publish(contester, vec![shared_child(0xa2, "own")], 1);
            fx.pass(0);
            assert_eq!(
                fx.listing(holder),
                vec!["held".to_owned()],
                "one body alone names it, so it renders"
            );

            fx.publish(
                contester,
                vec![shared_child(0xa2, "own"), shared_child(0xcc, "taken")],
                2,
            );
            fx.pass(60_000);

            assert!(fx.listing(holder).is_empty());
            assert_eq!(fx.listing(contester), vec!["own".to_owned()]);
            assert!(!fx.holds_contested());
        }
    }

    /// The claim lasts exactly as long as the contest: the body that stops
    /// naming the id leaves it to the body that still does.
    #[test]
    fn a_node_one_body_stops_naming_returns_to_the_other_scope() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xcc, "by-first")], 1);
        fx.publish(1, vec![shared_child(0xcc, "by-second")], 1);
        fx.pass(0);
        assert!(!fx.holds_contested());

        fx.publish(1, vec![shared_child(0xa2, "second-own")], 2);
        fx.pass(60_000);

        assert_eq!(fx.listing(0), vec!["by-first".to_owned()]);
        assert_eq!(fx.listing(1), vec!["second-own".to_owned()]);
    }

    /// The claim outlives the pass that recorded it. A scope whose record this
    /// pass could not read still names what it last named, so an unreachable
    /// record does not hand the id to the body the pass did open.
    #[test]
    fn a_contest_holds_while_one_side_does_not_resolve() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xcc, "by-first")], 1);
        fx.publish(1, vec![shared_child(0xcc, "by-second")], 1);
        fx.pass(0);

        fx.unreachable(1);
        fx.pass(60_000);

        assert!(fx.listing(0).is_empty());
        assert!(!fx.holds_contested());
    }

    /// A plane that stops answering is never re-opened, so no merge speaks for
    /// it. A thief that goes silent after one success must still lose the id.
    #[test]
    fn a_contested_id_departs_a_plane_this_pass_does_not_re_open() {
        let fx = TwoSharers::new();
        fx.publish(0, vec![shared_child(0xcc, "held")], 1);
        fx.pass(0);
        assert_eq!(
            fx.listing(0),
            vec!["held".to_owned()],
            "one body alone names it, so it renders"
        );

        fx.unreachable(0);
        fx.publish(1, vec![shared_child(0xcc, "taken")], 1);
        fx.pass(60_000);

        assert!(fx.listing(1).is_empty());
        assert!(!fx.holds_contested(), "and the silent plane keeps nothing");
    }

    /// The sweep is over nodes, not planes. A bookmarked scope root stays, and
    /// so does a node of this vault's own tree, whatever a grafted body names.
    #[test]
    fn the_contest_sweep_spares_a_scope_root_and_this_vaults_own_node() {
        const GRAFTED_NODE: [u8; 16] = [0xd1; 16];
        const OWN_NODE: [u8; 16] = [0xd2; 16];
        let mut snapshot = Snapshot::new(NodeId(VAULT_ROOT));
        for (id, parent) in [
            (SCOPE, None),
            (GRAFTED_NODE, Some(SCOPE)),
            (OWN_NODE, Some(VAULT_ROOT)),
        ] {
            snapshot.upsert_node(NodeMeta::new(NodeId(id), "n", NodeKind::Folder));
            if let Some(parent) = parent {
                snapshot.link_next(NodeId(parent), NodeId(id));
            }
        }
        let base = BaseSnapshot::new(snapshot);
        let read_seeds = RefCell::new(ScopeSeeds::new());
        let write_seeds = RefCell::new(ScopeSeeds::new());
        let own_descendants = RefCell::new(BTreeSet::new());
        let grafted_sharers = RefCell::new(GraftedSharers::new());
        let scope_roots = RefCell::new(BookmarkedScopeRoots::from([SCOPE]));
        let permissions = RefCell::new(BookmarkedPermissions::new());
        let claims = RefCell::new(ClaimRecord::default());
        let (events, _rx) = mpsc::unbounded();

        let departed = depart_contested(
            &ContestedNodes::from([SCOPE, OWN_NODE, GRAFTED_NODE]),
            &ScopeRender {
                base: &base,
                read_seeds: &read_seeds,
                write_seeds: &write_seeds,
                own_root: &VAULT_ROOT,
                own_descendants: &own_descendants,
                grafted_sharers: &grafted_sharers,
                scope_roots: &scope_roots,
                permissions: &permissions,
                claims: &claims,
                events: &events,
            },
        );

        assert!(departed);
        assert!(base.borrow().contains(NodeId(SCOPE)));
        assert!(base.borrow().contains(NodeId(OWN_NODE)));
        assert!(!base.borrow().contains(NodeId(GRAFTED_NODE)));
    }

    /// A scope-root body past the folder ceiling is refused whole: the record
    /// cannot hold its claim, so nothing it names may reach the render tree.
    /// The row still resolves, and the pass has already spent one of its
    /// resolves on it — a body re-authored under the bound grafts next pass.
    #[test]
    fn an_over_full_scope_root_body_grafts_nothing_and_still_resolves() {
        let over_full: Vec<ChildRef> = (0..=MAX_FOLDER_CHILDREN)
            .map(|i| {
                let mut id = [0xa1u8; 16];
                id[..8].copy_from_slice(&(i as u64).to_be_bytes());
                ChildRef {
                    id,
                    name: format!("padding-{i}"),
                    ipns_name: id.to_vec(),
                    kind: CoreNodeKind::Folder,
                    link_counter: 1,
                    unknown: PreservedFields::new(),
                }
            })
            .collect();
        let fx = RenderedScope::new(over_full);
        fx.bookmark();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        assert!(fx.reported.get(), "an over-full body is attributable");
        assert!(
            !fx.base.borrow().contains(NodeId(SCOPE)),
            "the refused body grafts no scope root",
        );
        assert!(fx.claims.borrow().named().is_empty(), "and claims nothing");
    }

    /// The steady state: the transport re-serves the record this vault already
    /// adopted on every later pass. That record is at the durable floor, so the
    /// gate refuses to re-adopt it — and the listing must still stand rather than
    /// vanish behind the refusal.
    #[test]
    fn a_re_resolve_at_the_durable_floor_keeps_the_listing_it_already_rendered() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);

        // Past the on-access damper, so the second pass genuinely re-resolves.
        assert_eq!(fx.pass(60_000), ResolutionClass::Granted);

        assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        assert!(fx.read_seeds.borrow().contains_key(&SCOPE));
        assert!(
            !fx.reported.get(),
            "the record already adopted is no replay"
        );
    }

    /// An edit a sharer or a write grantee makes to a published scope root.
    type Forgery = fn(&mut Envelope, &mut GrantSection);

    /// A scope root the gate refuses is a trust violation: the row fails, the
    /// member hears of it, and nothing of the refused body renders. Stage 2
    /// passes in each case, so the row classifies before the refusal.
    #[test]
    fn a_scope_root_the_gate_refuses_is_reported_and_never_rendered() {
        let forgeries: [(&str, Forgery); 2] = [
            ("a broken owner blob signature", |_, section| {
                section.owner_blob.signature[0] ^= 0x01;
            }),
            ("a root at another node id", |envelope, _| {
                envelope.id = [0x11; 16];
            }),
        ];
        for (forgery, edit) in forgeries {
            let mut fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
            fx.fixture = reencoded(
                shared_scope_fixture(vec![shared_child(0xa1, "photos")], Permission::Read),
                edit,
            );
            seed_scope_root(&fx.records, &fx.fixture, 1);
            fx.bookmark();

            assert_eq!(fx.pass(0), ResolutionClass::Unresolvable, "{forgery}");
            assert!(fx.reported.get(), "{forgery} is a trust verdict");
            assert!(fx.listing().is_empty(), "{forgery}");
            assert!(!fx.read_seeds.borrow().contains_key(&SCOPE), "{forgery}");
        }
    }

    /// The record at the durable floor is re-rendered without a second adopt,
    /// so its unseal is the gate's own stage 6: a body that will not open is
    /// reported, never read as an unchanged listing.
    #[test]
    fn a_record_at_the_floor_whose_body_will_not_open_is_reported() {
        let mut fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(!fx.reported.get());

        fx.fixture = reencoded(
            shared_scope_fixture(vec![shared_child(0xa1, "photos")], Permission::Read),
            |envelope, _| {
                let last = envelope.read_sealed.len() - 1;
                envelope.read_sealed[last] ^= 0x01;
            },
        );
        seed_scope_root(&fx.records, &fx.fixture, 1);

        assert_eq!(fx.pass(60_000), ResolutionClass::Unresolvable);
        assert!(
            fx.reported.get(),
            "a body that will not open is a trust verdict"
        );
    }

    /// A floor store that cannot commit the adoption is availability: nothing
    /// renders, and nobody is accused.
    #[test]
    fn an_adoption_the_floor_store_cannot_commit_accuses_nobody() {
        let fx = RenderedScope::new(vec![shared_child(0xa1, "photos")]);
        fx.bookmark();
        fx.floors.fail_floor_commits();

        assert_eq!(fx.pass(0), ResolutionClass::Granted);
        assert!(!fx.reported.get(), "availability accuses nobody");
        assert!(fx.listing().is_empty());
    }

    // -----------------------------------------------------------------------
    // The link-held read path (ADR 0024 D1, D2, D5; ADR 0025 D5).
    // -----------------------------------------------------------------------

    mod link_held {
        use super::*;
        use crate::facade::POINTER_PAYLOAD_VERSION;
        use crate::grants::accept::LinkHold;
        use crate::grants::invite::{EphemeralInvitee, LinkTerms, mint_invite_grant};
        use crate::grants::ledger::GrantRow;
        use crate::sync::pointer::{
            SessionRole, scope_pointer_name, scope_pointer_signer, seal_repoint,
        };
        use cipherbox_core::payload::RepointObject;

        const POINTER_SEED: [u8; 32] = [0x6a; 32];
        const LINK_SECRET: [u8; 32] = [0x4e; 32];
        const DEADLINE: UnixMillis = UnixMillis(5_000);
        /// A deadline no test pass reaches.
        const LATER: UnixMillis = UnixMillis(1_000_000);

        fn pointer_name() -> IpnsName {
            scope_pointer_name(&POINTER_SEED, &SCOPE)
        }

        /// The root name a write wave left behind.
        fn old_root_name() -> IpnsName {
            derive_write_name(&[0x78; 32], &SCOPE)
        }

        fn link_row(deadline: UnixMillis) -> GrantRow {
            mint_invite_grant(
                &sharer_signer(),
                &sharer_enc(),
                &OWNER_ROOT_POINTER_READ_KEY,
                &EphemeralInvitee::from_secret(&LINK_SECRET).expect("valid"),
                &SCOPE,
                &OWNER_ROOT_WRITE_SCOPE_SEED,
                &LinkTerms {
                    deadline,
                    conversion_permission: Permission::Write,
                    admission_cap: 5,
                },
            )
            .expect("the owner mints its link")
        }

        fn personal_row() -> GrantRow {
            mint_grant_row(
                &sharer_signer(),
                &sharer_enc(),
                &OWNER_ROOT_POINTER_READ_KEY,
                [0x03; IDENTITY_PUBLIC_LEN],
                &my_enc().public(),
                &SCOPE,
                scope_root_name().as_str().as_bytes(),
                Permission::Read,
            )
            .expect("contributory")
        }

        fn other_row() -> GrantRow {
            mint_grant_row(
                &sharer_signer(),
                &sharer_enc(),
                &OWNER_ROOT_POINTER_READ_KEY,
                [0x05; IDENTITY_PUBLIC_LEN],
                &someone_else(),
                &SCOPE,
                scope_root_name().as_str().as_bytes(),
                Permission::Read,
            )
            .expect("contributory")
        }

        /// Serve the owner's scope pointer, re-pointed at the root that stands,
        /// sealed and signed by `owner`.
        fn serve_pointer(fx: &RenderedScope, owner: &EcdsaSigner, sequence: u64) {
            let block = seal_repoint(
                SessionRole::Owner,
                &mut SeededEntropy::new(3),
                &OWNER_ROOT_POINTER_READ_KEY,
                POINTER_PAYLOAD_VERSION,
                owner,
                &RepointObject {
                    scope_id: SCOPE,
                    current_root: scope_root_name(),
                    write_epoch: 2,
                    min_read_epoch: 1,
                    prev_root: None,
                },
            )
            .expect("the owner seals its re-point");
            fx.records.seed_record(
                &EndpointId::new("e0"),
                pointer_name().as_str(),
                IpnsRecord::create_v2(
                    &scope_pointer_signer(&POINTER_SEED, &SCOPE),
                    &block,
                    sequence,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
        }

        /// Serve the scope root committing `rows`, at cut epoch `cut`.
        fn serve_root(fx: &mut RenderedScope, rows: Vec<GrantRow>, cut: u64, sequence: u64) {
            let fixture = owner_root_fixture(OwnerRootSpec {
                writer_pseudonym: &owner_root_pseudonym(),
                pointer_read_key: OWNER_ROOT_POINTER_READ_KEY,
                owner_identity: &sharer_signer(),
                owner_enc: &sharer_enc().public(),
                scope_id: SCOPE,
                root_id: SCOPE,
                children: vec![shared_child(0xa1, "photos")],
                child_scope_index: Vec::new(),
                grants: rows,
                parent_node_seed: None,
                owner_write_blob_epoch: None,
                write_history_link: Vec::new(),
            });
            fx.fixture = with_cut_epoch(fixture, &sharer_signer(), cut);
            seed_scope_root(&fx.records, &fx.fixture, sequence);
        }

        /// The bookmark a join leaves: the link keys, and the root name last
        /// seen — here the one a write wave has since moved off.
        fn join(fx: &RenderedScope) {
            join_with(fx, LINK_SECRET);
        }

        fn join_with(fx: &RenderedScope, secret: [u8; 32]) {
            let mut list = ReceivedSharesList::new();
            let share = ReceivedShare {
                scope_root_name: old_root_name().as_str().as_bytes().to_vec(),
                scope_id: SCOPE,
                sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                display_name: "photos-folder".to_owned(),
                permission: Permission::Read,
                pointer_read_key: SecretBytes::new(OWNER_ROOT_POINTER_READ_KEY),
            };
            let key = share.key();
            list.reconcile(share);
            list.hold_link(key, LinkHold::new(SecretBytes::new(secret), pointer_name()));
            fx.persist(&list).expect("the join persists");
        }

        fn stored(fx: &RenderedScope) -> (Vec<u8>, Option<LinkHold>) {
            let list = block_on(
                StagingReceivedShareStore::new(&fx.staging, &my_enc(), &fx.entropy).load(),
            )
            .expect("the list loads");
            let share = list.iter().next().expect("one bookmark");
            (
                share.scope_root_name.clone(),
                list.link_hold(&share.key()).cloned(),
            )
        }

        /// A root a write wave moved still opens: the holder follows the owner's
        /// re-point object to the root that stands, derives the link tag there,
        /// and heals its bookmark to that name.
        #[test]
        fn a_root_a_write_wave_moved_still_opens_through_the_pointer() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(DEADLINE)], 0, 1);

            assert_eq!(fx.forced_pass(0), ResolutionClass::Granted);
            assert_eq!(fx.listing(), vec!["photos".to_owned()]);
            let (root, hold) = stored(&fx);
            assert_eq!(root, scope_root_name().as_str().as_bytes());
            assert_eq!(
                hold.expect("the link keys stay until a personal blob lands")
                    .deadline,
                Some(DEADLINE),
                "the verified deadline is kept for the expired state"
            );
            assert_eq!(
                fx.permissions.borrow().get(&SCOPE),
                Some(&Permission::Read),
                "a link reads at read, whatever it converts to"
            );
        }

        /// ADR 0024 D2: the holder prefers its personal tag, and the pass that
        /// reads it drops the link keys. A link revoke after that leaves the
        /// grant standing.
        #[test]
        fn the_link_keys_drop_once_the_personal_blob_lands() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);
            assert_eq!(fx.forced_pass(0), ResolutionClass::Granted);
            assert!(stored(&fx).1.is_some());

            serve_root(&mut fx, vec![link_row(LATER), personal_row()], 0, 2);
            assert_eq!(fx.forced_pass(1_000), ResolutionClass::Granted);
            assert!(
                stored(&fx).1.is_none(),
                "the personal blob replaces the link keys"
            );

            serve_root(&mut fx, vec![personal_row()], 1, 3);
            assert_eq!(fx.forced_pass(2_000), ResolutionClass::Granted);
        }

        /// ADR 0025 D5: a link entry past its deadline stops the read with the
        /// state "expired", and a link gone after the last verified deadline is
        /// expired too; one gone before it was revoked.
        #[test]
        fn an_expired_deadline_stops_the_read_with_expired() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(DEADLINE)], 0, 1);
            assert_eq!(fx.forced_pass(0), ResolutionClass::Granted);
            assert!(fx.read_seeds.borrow().contains_key(&SCOPE));

            assert_eq!(fx.forced_pass(DEADLINE.0), ResolutionClass::Expired);
            assert!(
                !fx.read_seeds.borrow().contains_key(&SCOPE),
                "the holder stops reading through the link"
            );

            // The owner's sweep cut the link at its deadline.
            serve_root(&mut fx, vec![other_row()], 1, 2);
            assert_eq!(fx.forced_pass(DEADLINE.0 + 1), ResolutionClass::Expired);
        }

        #[test]
        fn a_link_cut_before_its_deadline_reads_as_revoked() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(DEADLINE)], 0, 1);
            assert_eq!(fx.forced_pass(0), ResolutionClass::Granted);

            serve_root(&mut fx, vec![other_row()], 1, 2);
            assert_eq!(fx.forced_pass(1_000), ResolutionClass::RevocationSignal);
        }

        /// A re-point object the owner code does not verify is a trust verdict,
        /// reported and never followed.
        #[test]
        fn a_re_point_the_owner_did_not_sign_is_refused_and_reported() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &other_sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);

            assert_eq!(fx.forced_pass(0), ResolutionClass::Unresolvable);
            assert!(fx.reported.get());
            assert_eq!(stored(&fx).0, old_root_name().as_str().as_bytes());
        }

        /// A join whose pointer no endpoint serves yet stays unresolvable, and
        /// the next pass retries it.
        #[test]
        fn a_join_with_no_pointer_served_yet_stays_unresolvable() {
            let fx = RenderedScope::new(Vec::new());
            join(&fx);

            assert_eq!(fx.forced_pass(0), ResolutionClass::Unresolvable);
            assert!(!fx.reported.get());
            assert!(
                stored(&fx).1.is_some(),
                "the link keys wait for the next pass"
            );
        }

        /// A committed personal blob this device cannot open leaves the link
        /// as its way in, on every pass, and the link keys stay.
        #[test]
        fn a_personal_blob_that_will_not_open_keeps_the_link_keys() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            let mut unopenable = personal_row();
            unopenable.ledger_entry.recipient_enc_pk = someone_else().to_bytes();
            serve_root(&mut fx, vec![link_row(LATER), unopenable], 0, 1);

            for at in [0, 1_000] {
                assert_eq!(
                    fx.forced_pass(at),
                    ResolutionClass::Granted,
                    "the share reads through the link"
                );
                assert_eq!(fx.listing(), vec!["photos".to_owned()]);
                assert!(
                    stored(&fx).1.is_some(),
                    "the link keys stay until a personal blob opens"
                );
            }
        }

        /// A transport that runs `during` once, at the first GET of a pass.
        struct MidPass<'a> {
            records: &'a InMemoryRecordStore,
            during: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
        }

        impl RecordTransport for MidPass<'_> {
            fn endpoints(&self) -> Vec<EndpointId> {
                self.records.endpoints()
            }

            async fn get_record(
                &self,
                endpoint: &EndpointId,
                routing_key: &str,
                max_bytes: usize,
                bearer: Option<&str>,
            ) -> SeamResult<Option<Vec<u8>>> {
                let during = self.during.borrow_mut().take();
                if let Some(during) = during {
                    during();
                }
                self.records
                    .get_record(endpoint, routing_key, max_bytes, bearer)
                    .await
            }

            async fn put_record(
                &self,
                endpoint: &EndpointId,
                routing_key: &str,
                record: &[u8],
            ) -> SeamResult<()> {
                self.records.put_record(endpoint, routing_key, record).await
            }
        }

        /// A join that lands while a pass awaits the network survives the
        /// pass's own write-back of the link hold it changed.
        #[test]
        fn a_join_during_a_pass_is_not_lost() {
            const JOINED: [u8; 16] = [0x6b; 16];
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);
            let transport = MidPass {
                records: &fx.records,
                during: RefCell::new(Some(Box::new(|| {
                    let enc = my_enc();
                    let store = StagingReceivedShareStore::new(&fx.staging, &enc, &fx.entropy);
                    let mut list = block_on(store.load()).expect("the list loads");
                    list.reconcile(ReceivedShare {
                        scope_root_name: derive_write_name(&[0x79; 32], &JOINED)
                            .as_str()
                            .as_bytes()
                            .to_vec(),
                        scope_id: JOINED,
                        sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                        display_name: String::new(),
                        permission: Permission::Read,
                        pointer_read_key: SecretBytes::new(OWNER_ROOT_POINTER_READ_KEY),
                    });
                    block_on(store.persist(&list)).expect("the join persists");
                }))),
            };

            assert_eq!(
                fx.pass_over(&transport, 0, ResolveMode::NoCache),
                ResolutionClass::Granted
            );
            let list = block_on(
                StagingReceivedShareStore::new(&fx.staging, &my_enc(), &fx.entropy).load(),
            )
            .expect("the list loads");
            let scopes: BTreeSet<[u8; 16]> = list.iter().map(|share| share.scope_id).collect();
            assert_eq!(scopes, BTreeSet::from([SCOPE, JOINED]));
            let healed = list
                .iter()
                .find(|share| share.scope_id == SCOPE)
                .expect("the held bookmark stays");
            assert_eq!(
                healed.scope_root_name,
                scope_root_name().as_str().as_bytes(),
                "the pass's own heal lands too"
            );
        }

        /// ADR 0024 D5: a link-held read renders only a root the pointer
        /// vouched for this pass. With the pointer unanswered after a write
        /// wave, the stored root is not read and the last verdict stands.
        #[test]
        fn a_pointer_that_goes_unavailable_does_not_render_the_stored_root() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);
            assert_eq!(fx.forced_pass(0), ResolutionClass::Granted);

            fx.records.fail_get_for(pointer_name().as_str());
            let reads = fx.records.get_count(scope_root_name().as_str());
            assert_eq!(fx.forced_pass(1_000), ResolutionClass::Granted);
            assert_eq!(
                fx.records.get_count(scope_root_name().as_str()),
                reads,
                "no root the pointer did not vouch for is read"
            );
            assert!(!fx.reported.get(), "availability accuses nobody");
        }

        /// A first read with no pointer answer keeps the link keys, and a later
        /// pass reads the folder.
        #[test]
        fn a_first_read_that_fails_is_retried_by_a_later_pass() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);
            fx.records.fail_get_for(pointer_name().as_str());

            assert_eq!(fx.forced_pass(0), ResolutionClass::Unresolvable);
            assert!(stored(&fx).1.is_some());

            fx.records.heal_get_for(pointer_name().as_str());
            assert_eq!(fx.forced_pass(1_000), ResolutionClass::Granted);
            assert_eq!(fx.listing(), vec!["photos".to_owned()]);
        }

        /// Capped passes reach every held bookmark in turn: the one a full
        /// pass left out goes first in the next.
        #[test]
        fn a_capped_pass_reaches_the_held_bookmark_the_last_one_left_out() {
            let fx = RenderedScope::new(Vec::new());
            let scopes: Vec<[u8; 16]> = (0..=MAX_RESOLVES_PER_PASS / 2)
                .map(|i| {
                    let mut scope = [0x60; 16];
                    scope[15] = u8::try_from(i).expect("a small list");
                    scope
                })
                .collect();
            let mut list = ReceivedSharesList::new();
            for scope in &scopes {
                let share = ReceivedShare {
                    scope_root_name: derive_write_name(&[0x78; 32], scope)
                        .as_str()
                        .as_bytes()
                        .to_vec(),
                    scope_id: *scope,
                    sharer_identity_pk: sharer_signer().verifying_key().to_sec1(),
                    display_name: String::new(),
                    permission: Permission::Read,
                    pointer_read_key: SecretBytes::new(OWNER_ROOT_POINTER_READ_KEY),
                };
                let key = share.key();
                list.reconcile(share);
                list.hold_link(
                    key,
                    LinkHold::new(
                        SecretBytes::new(LINK_SECRET),
                        scope_pointer_name(&POINTER_SEED, scope),
                    ),
                );
            }
            fx.persist(&list).expect("the joins persist");
            let unread = || -> Vec<[u8; 16]> {
                scopes
                    .iter()
                    .filter(|scope| {
                        fx.records
                            .get_count(scope_pointer_name(&POINTER_SEED, scope).as_str())
                            == 0
                    })
                    .copied()
                    .collect()
            };

            fx.forced_pass(0);
            let [left_out] = unread()[..] else {
                panic!("one full pass leaves exactly one held bookmark out");
            };
            fx.forced_pass(1_000);
            assert!(
                !unread().contains(&left_out),
                "the next pass reads the bookmark the first one left out"
            );
        }

        /// The pass's write-back of the list waits for a writer that holds it,
        /// and lands once that writer lets go.
        #[test]
        fn the_refresh_write_back_waits_for_a_writer_holding_the_list() {
            let mut fx = RenderedScope::new(Vec::new());
            join(&fx);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);
            let writer = fx.list_lock.try_lock().expect("the list is free");
            let (events, _rx) = mpsc::unbounded();
            let mut pass = pin!(fx.refresh_over(&fx.records, &events, 0, ResolveMode::NoCache));
            let mut cx = Context::from_waker(Waker::noop());

            assert!(pass.as_mut().poll(&mut cx).is_pending());
            assert_eq!(
                stored(&fx).0,
                old_root_name().as_str().as_bytes(),
                "the heal waits for the writer"
            );
            drop(writer);
            block_on(pass);
            assert_eq!(stored(&fx).0, scope_root_name().as_str().as_bytes());
        }

        /// A stored link secret that is no scalar reads nothing: the verdict is
        /// unresolvable, not a skipped share.
        #[test]
        fn a_stored_secret_that_is_no_scalar_is_unresolvable() {
            let mut fx = RenderedScope::new(Vec::new());
            join_with(&fx, [0; 32]);
            serve_pointer(&fx, &sharer_signer(), 1);
            serve_root(&mut fx, vec![link_row(LATER)], 0, 1);

            assert_eq!(fx.forced_pass(0), ResolutionClass::Unresolvable);
            assert!(
                fx.verdicts
                    .borrow()
                    .contains_key(&(sharer_signer().verifying_key().to_sec1(), SCOPE)),
                "the share carries a verdict"
            );
            assert!(fx.listing().is_empty());
        }
    }
}
