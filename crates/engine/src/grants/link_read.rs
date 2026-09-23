//! PROTOTYPE (throwaway): instant read from a read link's grant blob, before
//! the owner converts the claim. See `crates/engine/PROTOTYPE.md`.

use cipherbox_core::kdf;
use cipherbox_core::seal::{AadContext, Permission, STRUCT_TAG_GRANT_BLOB, open_grant_blob};
use cipherbox_core::suite::secret::SecretBytes;
use zeroize::Zeroizing;

use crate::gate::{Candidate, GateError, ReaderContext, SeedBlob, adopt_deferred};
use crate::seams::{ContactLabel, FloorStore, SharerScopedFloorStore};

use super::accept::{
    AcceptError, AcceptOutcome, BookmarkKey, ReceivedShare, ReceivedShareStore, ReceivedSharesList,
};
use super::contact::Contact;
use super::invite::EphemeralInvitee;
use super::ledger::{PublishedGrantBlob, recipient_blinded_tag, self_locate};

/// The label a link-held share renders under until the owner's share pointer
/// heals it. The fragment carries no folder name.
pub const LINK_SHARE_LABEL: &str = "shared via link";

/// Accept a scope root through the link's own grant blob: the same steps as
/// [`accept_share`](super::accept_share), with the ephemeral encryption subkey
/// in place of this device's, and the fragment's owner contact in place of a
/// mailbox-sender-bound one. `Ok(None)` for a write link: out of scope.
#[allow(clippy::too_many_arguments)]
pub async fn accept_link_share<F: FloorStore, S: ReceivedShareStore>(
    floors: &F,
    store: &S,
    owner: &Contact,
    invitee: &EphemeralInvitee,
    contact_label_seed: &SecretBytes,
    scope_root_name: &[u8],
    candidate: &Candidate,
    grant_blobs: &[PublishedGrantBlob],
    vault_root_scope: &[u8; 16],
    received: &mut ReceivedSharesList,
) -> Result<Option<AcceptOutcome>, AcceptError> {
    if candidate.name.as_str().as_bytes() != scope_root_name {
        return Err(AcceptError::NameMismatch);
    }
    if &candidate.envelope.scope == vault_root_scope {
        return Err(AcceptError::OwnVaultScope);
    }
    let tag = recipient_blinded_tag(invitee.enc_secret(), &owner.enc_subkey(), scope_root_name)
        .ok_or(AcceptError::UnusableSharerKey)?;
    let blob = self_locate(grant_blobs, &tag).ok_or(AcceptError::NoBlobAtTag)?;
    let permission = candidate
        .grant_section
        .commitment
        .entries
        .iter()
        .find(|e| e.tag == tag)
        .map(|e| e.permission)
        .ok_or(AcceptError::UncommittedTag)?;
    if permission != Permission::Read {
        return Ok(None);
    }
    let grant_aad = AadContext {
        v: candidate.envelope.v,
        id: candidate.envelope.id,
        scope: candidate.envelope.scope,
        epoch: candidate.envelope.epoch,
        struct_tag: STRUCT_TAG_GRANT_BLOB,
    };
    let grant = open_grant_blob(
        invitee.enc_secret(),
        &blob.enc,
        &grant_aad,
        &blob.ciphertext,
    )
    .map_err(AcceptError::GrantBlobOpen)?;
    let node_seed = kdf::node_seed(grant.read_scope_seed(), &candidate.envelope.id);
    let read_key = Zeroizing::new(*kdf::read_key(node_seed.as_bytes()).as_bytes());
    let owner_identity = owner.identity_pk();
    let reader = ReaderContext {
        owner_identity: &owner_identity,
        scope_id: candidate.envelope.scope,
        read_key: &read_key,
        parent_node_seed: None,
        seed_blob: Some(SeedBlob::Grantee {
            enc_secret: invitee.enc_secret(),
            enc: blob.enc,
            ciphertext: blob.ciphertext.clone(),
            aad: grant_aad,
        }),
    };
    let sharer = owner_identity.to_sec1();
    let floors =
        &SharerScopedFloorStore::granted_by(floors, ContactLabel::of(contact_label_seed, &sharer));
    let (pending, _) = adopt_deferred(floors, &reader, candidate)
        .await
        .map_err(AcceptError::Gate)?;

    let key: BookmarkKey = (sharer, candidate.envelope.scope);
    // A personal bookmark already held wins: the link adds nothing to it.
    let personal = received.find(&key).is_some() && received.link_secret(&key).is_none();
    if !personal {
        received.reconcile(ReceivedShare {
            scope_root_name: scope_root_name.to_vec(),
            scope_id: candidate.envelope.scope,
            sharer_identity_pk: sharer,
            display_name: LINK_SHARE_LABEL.to_owned(),
            permission,
            pointer_read_key: SecretBytes::new(*grant.pointer_read_key()),
        });
        received.set_link(key, invitee.secret().clone());
        store
            .persist(received)
            .await
            .map_err(AcceptError::Persist)?;
    }
    let adopted = pending
        .commit(floors)
        .await
        .map_err(|e| AcceptError::Gate(GateError::Seam(e)))?;
    Ok(Some(AcceptOutcome {
        scope_id: candidate.envelope.scope,
        sequence: adopted.sequence,
        permission,
        newly_added: !personal,
    }))
}
