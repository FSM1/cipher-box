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

use cipherbox_core::seal::verify_grant_set_bound;
use cipherbox_core::suite::ecdsa::{EcdsaSignature, EcdsaVerifier};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::content::Gateway;
use crate::gate::Candidate;
use crate::gate::floor;
use crate::net::rotation::scope_name;
use crate::net::{assemble_candidate, fanout_get_verify};
use crate::seams::{FloorStore, Http, RecordTransport};

use super::accept::ReceivedShare;
use super::ledger::{recipient_blinded_tag, self_locate_signed};
use super::revocation::ResolutionFacts;

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
}

impl<T: RecordTransport, H: Http, F: FloorStore> ReceivedShareStatus<'_, T, H, F> {
    /// The facts `share`'s scope root supports right now.
    ///
    /// Every failure short of the durable floor read reports
    /// `owner_signed_record: false` — an unparsable bookmark, an unresolvable
    /// name, an unassemblable record, and a commitment that does not verify
    /// under the contact-anchored sharer are all "no fresh owner-signed record",
    /// never a revocation ([`super::revocation`]).
    pub(crate) async fn facts(
        &self,
        share: &ReceivedShare,
        sharer_identity: &EcdsaVerifier,
        sharer_enc_pub: &X25519Public,
    ) -> ResolutionFacts {
        let epoch_floor = floor::read_epoch_floor(self.floors, &share.scope_id)
            .await
            .ok()
            .flatten()
            .unwrap_or(0);
        let unresolved = ResolutionFacts {
            owner_signed_record: false,
            blob_present: false,
            record_epoch: 0,
            epoch_floor,
        };

        let Ok(name) = scope_name(&share.scope_root_name) else {
            return unresolved;
        };
        let Some((_, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
            return unresolved;
        };
        let Ok(candidate) =
            assemble_candidate(self.gateway, self.http, &name, &record_bytes, None).await
        else {
            return unresolved;
        };
        let section = &candidate.grant_section;
        let Some(commitment_sig) = EcdsaSignature::from_compact(&section.commitment_sig) else {
            return unresolved;
        };
        if verify_grant_set_bound(
            sharer_identity,
            &section.commitment,
            &commitment_sig,
            &share.scope_root_name,
        )
        .is_err()
        {
            return unresolved;
        }

        ResolutionFacts {
            owner_signed_record: true,
            blob_present: self.blob_present(share, sharer_enc_pub, &candidate),
            record_epoch: candidate.envelope.epoch,
            epoch_floor,
        }
    }

    /// Whether this device is still in the set the owner committed *and* the
    /// record carries its blob. The owner-signed commitment is the authority, so
    /// a blob at an uncommitted tag is not a grant — it counts as removal, the
    /// same verdict the accept flow reaches by refusing an uncommitted tag.
    fn blob_present(
        &self,
        share: &ReceivedShare,
        sharer_enc_pub: &X25519Public,
        candidate: &Candidate,
    ) -> bool {
        let Some(tag) =
            recipient_blinded_tag(self.enc_secret, sharer_enc_pub, &share.scope_root_name)
        else {
            return false;
        };
        let section = &candidate.grant_section;
        section.commitment.entries.iter().any(|e| e.tag == tag)
            && self_locate_signed(&section.grant_blobs, &tag).is_some()
    }
}
