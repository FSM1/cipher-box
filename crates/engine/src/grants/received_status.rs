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
    /// The facts `share`'s scope root supports right now: resolve it, then hold
    /// what came back to the contact anchors ([`facts_from`]).
    ///
    /// Every failure short of the durable floor read reports
    /// `owner_signed_record: false` — an unparsable bookmark, an unresolvable
    /// name and an unassemblable record are all "no fresh owner-signed record",
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
        facts_from(
            &candidate,
            &share.scope_root_name,
            self.enc_secret,
            sharer_identity,
            sharer_enc_pub,
            epoch_floor,
        )
    }
}

/// What a resolved scope root supports, as a pure function of the record and the
/// verified contact anchors.
///
/// A commitment that does not verify under `sharer_identity`, or that is bound
/// to another name, is not a fresh owner-signed record — an untrusted party
/// republishing at that name proves nothing about your grant, so it classifies
/// as unresolvable rather than as a removal.
pub(crate) fn facts_from(
    candidate: &Candidate,
    scope_root_name: &[u8],
    my_enc_secret: &X25519Secret,
    sharer_identity: &EcdsaVerifier,
    sharer_enc_pub: &X25519Public,
    epoch_floor: u64,
) -> ResolutionFacts {
    let section = &candidate.grant_section;
    let owner_signed = EcdsaSignature::from_compact(&section.commitment_sig).is_some_and(|sig| {
        verify_grant_set_bound(sharer_identity, &section.commitment, &sig, scope_root_name).is_ok()
    });
    if !owner_signed {
        return ResolutionFacts {
            owner_signed_record: false,
            blob_present: false,
            record_epoch: 0,
            epoch_floor,
        };
    }
    // The owner-signed commitment is the authority, so a blob at an uncommitted
    // tag is not a grant: it counts as removal, the same verdict the accept flow
    // reaches by refusing an uncommitted tag.
    let blob_present = recipient_blinded_tag(my_enc_secret, sharer_enc_pub, scope_root_name)
        .is_some_and(|tag| {
            section.commitment.entries.iter().any(|e| e.tag == tag)
                && self_locate_signed(&section.grant_blobs, &tag).is_some()
        });
    ResolutionFacts {
        owner_signed_record: true,
        blob_present,
        record_epoch: candidate.envelope.epoch,
        epoch_floor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::ipns::IpnsName;
    use cipherbox_core::seal::Permission;
    use cipherbox_core::suite::ecdsa::{EcdsaSigner, IDENTITY_PUBLIC_LEN};

    use crate::rotation::derive_write_name;
    use crate::testkit::{
        OWNER_ROOT_EPOCH, OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootSpec, owner_root_fixture,
    };

    use super::super::ledger::mint_grant_row;
    use super::super::revocation::{ResolutionClass, classify};

    const SCOPE: [u8; 16] = [0x5c; 16];
    const SHARER_IDENTITY_PK: [u8; IDENTITY_PUBLIC_LEN] = [0x02; IDENTITY_PUBLIC_LEN];

    fn sharer_signer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar")
    }

    /// The sharer's encryption subkey — the blinded tag's owner-side half.
    fn sharer_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x33; 32])
    }

    /// This device's encryption subkey.
    fn my_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x44; 32])
    }

    fn scope_root_name() -> IpnsName {
        derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE)
    }

    /// A resolved scope root at the shared scope, committing a grant to each
    /// recipient in `recipients`.
    fn resolved(sharer: &EcdsaSigner, recipients: &[&X25519Public]) -> Candidate {
        let name = scope_root_name();
        let grants = recipients
            .iter()
            .map(|recipient| {
                mint_grant_row(
                    sharer,
                    &sharer_enc(),
                    SHARER_IDENTITY_PK,
                    recipient,
                    &SCOPE,
                    name.as_str().as_bytes(),
                    Permission::Read,
                )
                .expect("a contributory recipient key")
            })
            .collect();
        let fixture = owner_root_fixture(OwnerRootSpec {
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
        });
        Candidate {
            name,
            record_bytes: Vec::new(),
            grant_section: fixture.grant_section,
            envelope: fixture.envelope,
        }
    }

    fn classify_at(candidate: &Candidate, sharer: &EcdsaSigner, floor: u64) -> ResolutionClass {
        classify(&facts_from(
            candidate,
            scope_root_name().as_str().as_bytes(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            floor,
        ))
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

    /// The definitive removal: the owner republished the committed set without
    /// you, so a fresh owner-signed record carries no blob at your tag.
    #[test]
    fn a_fresh_owner_signed_record_without_your_blob_is_a_revocation_signal() {
        let sharer = sharer_signer();
        let someone_else = X25519Secret::from_scalar([0x55; 32]).public();
        let candidate = resolved(&sharer, &[&someone_else]);
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
            scope_root_name().as_str().as_bytes(),
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            OWNER_ROOT_EPOCH,
        );
        assert!(
            facts.owner_signed_record,
            "the owner's own commitment still verifies"
        );
        assert_eq!(classify(&facts), ResolutionClass::RevocationSignal);
    }

    /// A record another party republished at that name proves nothing about your
    /// grant, so it is never read as a removal.
    #[test]
    fn a_record_the_sharer_did_not_sign_is_unresolvable_never_a_revocation() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let impostor = EcdsaSigner::from_scalar(&[0x71; 32]).expect("valid scalar");

        assert_eq!(
            classify_at(&candidate, &impostor, OWNER_ROOT_EPOCH),
            ResolutionClass::Unresolvable,
        );
    }

    /// The same holds for a commitment bound to some other scope root: it is the
    /// sharer's signature over a different name, not a verdict on this one.
    #[test]
    fn a_commitment_bound_to_another_name_is_unresolvable() {
        let sharer = sharer_signer();
        let candidate = resolved(&sharer, &[&my_enc().public()]);
        let facts = facts_from(
            &candidate,
            b"some-other-scope-root",
            &my_enc(),
            &sharer.verifying_key(),
            &sharer_enc().public(),
            OWNER_ROOT_EPOCH,
        );
        assert_eq!(classify(&facts), ResolutionClass::Unresolvable);
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
}
