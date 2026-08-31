//! The recipient's own mailbox leg: the pull that turns a delivered share
//! pointer into an accepted share (blueprint/engine.md "Mailbox logic": the
//! poll rides the sync tick).
//!
//! A grantee holds no pointer of its own to hand a host command, so discovery
//! cannot live above the facade — the tick polls, and every pointer it finds
//! runs the same [`accept_share`] flow a host-driven accept runs, gate and all.
//!
//! Two rules this leg adds to that flow:
//!
//! - **Only this arm's items.** A payload that does not decode as a
//!   [`SharePointer`] belongs to another consumer of the same inbox and is left
//!   where it is, un-acked. So is a pointer from a sender this vault never
//!   imported: the contact book is the accept's only trust anchor, and an item
//!   with no anchor is not this arm's to retire.
//! - **One item never denies the rest.** A refusal is reported and the pass
//!   moves on, so one hostile or unreachable scope root cannot stall delivery of
//!   the honest pointers behind it.

use core::cell::RefCell;
use std::collections::BTreeMap;

use cipherbox_core::suite::ecdsa::IDENTITY_PUBLIC_LEN;
use cipherbox_core::suite::x25519::X25519Secret;
use futures_channel::mpsc;

use crate::content::Gateway;
use crate::entropy::Entropy;
use crate::facade::{Event, emit_trust_violation, published_grant_blobs};
use crate::mailbox::{VerifiedMailboxItem, poll_verified};
use crate::net::rotation::scope_name;
use crate::net::{assemble_candidate, fanout_get_verify};
use crate::seams::{FloorStore, Http, Mailbox, RecordTransport, StagingStore};

use super::accept::{AcceptError, ReceivedShareStore, SharePointer, accept_share};
use super::contact::Contact;
use super::contact_store::{ContactStore, StagingContactStore};
use super::received_share_store::StagingReceivedShareStore;

/// How many pointers one pass accepts. Each costs a fan-out GET, a head fetch
/// and a durable persist; the rest stay on the inbox for the next pass, which
/// until-acked retention guarantees they survive.
const MAX_ACCEPTS_PER_PASS: usize = 8;

/// The seams one mailbox pull reads, plus this device's own encryption subkey —
/// the seal's recipient half and the self-locating tag's other half. Borrowed:
/// the session stays its terminal owner.
pub(crate) struct ShareInbox<'a, M, T, H, F> {
    /// The inbox the pointers arrive on.
    pub mailbox: &'a M,
    /// The record plane a pointed-at scope root resolves over.
    pub transport: &'a T,
    /// The content read source for the record's head block.
    pub gateway: &'a Gateway,
    /// The HTTP seam that fetch rides.
    pub http: &'a H,
    /// The durable floors the adoption gate reads and advances.
    pub floors: &'a F,
    /// This device's encryption subkey.
    pub enc_secret: &'a X25519Secret,
}

impl<M: Mailbox, T: RecordTransport, H: Http, F: FloorStore> ShareInbox<'_, M, T, H, F> {
    /// Accept every share pointer on the inbox that a contact this vault
    /// imported sent. The render tree moves on the received-share leg that
    /// follows, so this emits no repaint of its own.
    ///
    /// `v` is the envelope version the pointer was sealed under; a payload from
    /// any other does not open and never reaches this arm.
    pub(crate) async fn pull<St, E>(
        &self,
        staging: &St,
        entropy: &RefCell<E>,
        v: u64,
        events: &mpsc::UnboundedSender<Event>,
    ) where
        St: StagingStore,
        E: Entropy,
    {
        let Ok(items) = poll_verified(self.mailbox, self.enc_secret, v).await else {
            return;
        };
        // Ahead of both durable loads, which cost a seal-open each: an inbox
        // carrying nothing for this arm spends neither.
        let pointers: Vec<(&VerifiedMailboxItem, SharePointer)> = items
            .iter()
            .filter_map(|item| Some((item, SharePointer::decode(&item.payload).ok()?)))
            .take(MAX_ACCEPTS_PER_PASS)
            .collect();
        if pointers.is_empty() {
            return;
        }
        let Ok(contacts) = StagingContactStore::new(staging, self.enc_secret, entropy)
            .contacts()
            .await
        else {
            return;
        };
        let by_identity: BTreeMap<[u8; IDENTITY_PUBLIC_LEN], &Contact> = contacts
            .iter()
            .map(|contact| (contact.identity_pk().to_sec1(), contact))
            .collect();

        let store = StagingReceivedShareStore::new(staging, self.enc_secret, entropy);
        let Ok(mut received) = store.load().await else {
            return;
        };

        for (item, pointer) in pointers {
            let Some(contact) = by_identity.get(&item.sender_identity.to_sec1()) else {
                continue;
            };
            let Ok(name) = scope_name(&pointer.scope_root_name) else {
                continue;
            };
            let Some((_, record_bytes)) = fanout_get_verify(self.transport, &name).await else {
                continue;
            };
            let Ok(candidate) =
                assemble_candidate(self.gateway, self.http, &name, &record_bytes, None).await
            else {
                continue;
            };
            let blobs = published_grant_blobs(&candidate.grant_section);
            match accept_share(
                self.floors,
                self.mailbox,
                &store,
                item,
                contact,
                self.enc_secret,
                &candidate,
                &blobs,
                &mut received,
            )
            .await
            {
                Ok(_) => (),
                Err(e) => report(events, name.as_str(), &e),
            }
        }
    }
}

/// Surface an accept refusal that is a verdict on the record rather than on the
/// pass: a gate rejection, and the binds that hold a pointer to the contact that
/// sent it. Every other arm is an unreachable or unwritable pass the next one
/// retries, and the item stays un-acked either way.
fn report(events: &mpsc::UnboundedSender<Event>, name: &str, error: &AcceptError) {
    let attributable = match error {
        AcceptError::SharerMismatch | AcceptError::NameMismatch | AcceptError::UncommittedTag => {
            true
        }
        AcceptError::Gate(e) => e.rejection().is_some(),
        _ => false,
    };
    if attributable {
        emit_trust_violation(events, name, error);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cipherbox_core::ipns::{IpnsName, IpnsRecord};
    use cipherbox_core::kdf;
    use cipherbox_core::seal::Permission;
    use cipherbox_core::suite::contact::ContactCode;
    use cipherbox_core::suite::ecdsa::EcdsaSigner;

    use crate::content::{Gateway, GatewaySource};
    use crate::mailbox::post_sealed;
    use crate::rotation::derive_write_name;
    use crate::seams::{EndpointId, HttpResponse};
    use crate::testkit::fakes::{
        InMemoryFloorStore, InMemoryMailbox, InMemoryMailboxHub, InMemoryRecordStore,
        InMemoryStagingStore, ScriptedHttp,
    };
    use crate::testkit::{
        OWNER_ROOT_WRITE_SCOPE_SEED, OwnerRootFixture, OwnerRootSpec, SeededEntropy, block_on,
        owner_root_fixture,
    };

    use super::super::ledger::mint_grant_row;

    /// The envelope version the fixture authors and the pointer seals under.
    const V: u64 = 1;
    const SCOPE: [u8; 16] = [0x5c; 16];

    fn sharer() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x31; 32]).expect("valid scalar")
    }

    /// A sender the recipient's book has never held.
    fn stranger() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x32; 32]).expect("valid scalar")
    }

    fn sharer_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x33; 32])
    }

    fn me() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x43; 32]).expect("valid scalar")
    }

    fn my_enc() -> X25519Secret {
        X25519Secret::from_scalar([0x44; 32])
    }

    fn scope_root_name() -> IpnsName {
        derive_write_name(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE)
    }

    /// The sharer's published scope root, committing one read grant to me.
    fn published() -> OwnerRootFixture {
        let name = scope_root_name();
        let grants = vec![
            mint_grant_row(
                &sharer(),
                &sharer_enc(),
                sharer().verifying_key().to_sec1(),
                &my_enc().public(),
                &SCOPE,
                name.as_str().as_bytes(),
                Permission::Read,
            )
            .expect("a contributory recipient key"),
        ];
        owner_root_fixture(OwnerRootSpec {
            owner_identity: &sharer(),
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

    /// The recipient's whole world: the record plane serving the sharer's scope
    /// root, this device's own inbox, and its durable stores.
    struct Inbox {
        fixture: OwnerRootFixture,
        records: InMemoryRecordStore,
        http: ScriptedHttp,
        gateway: Gateway,
        hub: InMemoryMailboxHub,
        mailbox: InMemoryMailbox,
        floors: InMemoryFloorStore,
        staging: InMemoryStagingStore,
        entropy: RefCell<SeededEntropy>,
    }

    impl Inbox {
        fn new() -> Self {
            let fixture = published();
            let endpoint = EndpointId::new("e0");
            let records = InMemoryRecordStore::new(vec![endpoint.clone()]);
            records.seed_record(
                &endpoint,
                fixture.name.as_str(),
                IpnsRecord::create_v2(
                    &kdf::ipns_keypair(
                        kdf::write_seed(&OWNER_ROOT_WRITE_SCOPE_SEED, &SCOPE).as_bytes(),
                    ),
                    format!("/ipfs/{}", fixture.head_cid_str).as_bytes(),
                    1,
                    2_000_000_000,
                    "2099-01-01T00:00:00Z",
                )
                .marshal(),
            );
            let hub = InMemoryMailboxHub::default();
            let mailbox = hub.mailbox_for(&me().verifying_key().to_sec1());
            Self {
                fixture,
                records,
                http: ScriptedHttp::default(),
                gateway: Gateway {
                    accelerator: None,
                    public_fallbacks: vec![GatewaySource::public("https://gateway.invalid")],
                },
                hub,
                mailbox,
                floors: InMemoryFloorStore::default(),
                staging: InMemoryStagingStore::default(),
                entropy: RefCell::new(SeededEntropy::new(5)),
            }
        }

        /// Import `peer` into this vault's contact book, as an out-of-band code
        /// hand-off does.
        fn import(&self, peer: &EcdsaSigner, peer_enc: &X25519Secret) {
            block_on(
                StagingContactStore::new(&self.staging, &my_enc(), &self.entropy)
                    .record(&ContactCode::create(peer, peer_enc.public()).encode()),
            )
            .expect("the peer's code imports");
        }

        /// Post `payload` to this device's inbox, sealed and signed by `sender`.
        fn post(&self, sender: &EcdsaSigner, payload: &[u8], idempotency_key: &str) {
            block_on(post_sealed(
                &self.hub.mailbox_for(b"sender"),
                &my_enc().public(),
                &me().verifying_key(),
                &[0x51; 32],
                V,
                sender,
                payload,
                idempotency_key,
            ))
            .expect("the sealed item posts");
        }

        /// The pointer the sharer's grant would have delivered.
        fn pointer(&self) -> Vec<u8> {
            SharePointer {
                scope_root_name: scope_root_name().as_str().as_bytes().to_vec(),
                sharer_identity_pk: sharer().verifying_key().to_sec1(),
                display_name: "shared-folder".to_owned(),
                permission: Permission::Read,
            }
            .encode()
        }

        /// One pull pass, with the head block its resolve fetches served.
        fn pull(&self) -> Vec<Event> {
            self.http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: self.fixture.head_block.clone(),
            });
            let (sender, mut events) = mpsc::unbounded();
            block_on(
                ShareInbox {
                    mailbox: &self.mailbox,
                    transport: &self.records,
                    gateway: &self.gateway,
                    http: &self.http,
                    floors: &self.floors,
                    enc_secret: &my_enc(),
                }
                .pull(&self.staging, &self.entropy, V, &sender),
            );
            drop(sender);
            let mut drained = Vec::new();
            while let Ok(event) = events.try_recv() {
                drained.push(event);
            }
            drained
        }

        /// The scope roots this vault has durably bookmarked.
        fn bookmarked(&self) -> Vec<[u8; 16]> {
            block_on(StagingReceivedShareStore::new(&self.staging, &my_enc(), &self.entropy).load())
                .expect("the list loads")
                .iter()
                .map(|share| share.scope_id)
                .collect()
        }

        fn inbox_len(&self) -> usize {
            block_on(self.mailbox.poll())
                .expect("the inbox answers")
                .len()
        }
    }

    /// The bug this leg closes: with nothing but a delivered pointer and the
    /// sharer in the book, the tick's own pass adopts the share — no host
    /// command, and no pointer for a host to hand one.
    #[test]
    fn a_delivered_pointer_is_accepted_on_the_pass_that_finds_it() {
        let fx = Inbox::new();
        fx.import(&sharer(), &sharer_enc());
        fx.post(&sharer(), &fx.pointer(), "share-1");

        let events = fx.pull();

        assert_eq!(fx.bookmarked(), vec![SCOPE]);
        assert_eq!(fx.inbox_len(), 0, "and acks only what it made durable");
        assert!(events.is_empty(), "an honest share is no abuse report");
    }

    /// The contact book is the accept's only trust anchor. An item with no
    /// anchor is not this arm's to retire, so it stays for its transport TTL
    /// rather than being acked away before the peer is ever imported.
    #[test]
    fn a_pointer_from_a_sender_this_vault_never_imported_stays_on_the_inbox() {
        let fx = Inbox::new();
        fx.post(&stranger(), &fx.pointer(), "share-1");

        fx.pull();

        assert!(fx.bookmarked().is_empty(), "nothing was adopted");
        assert_eq!(fx.inbox_len(), 1, "and nothing was acked away");
    }

    /// One inbox, several consumers. A payload this arm cannot read is another
    /// arm's item and must survive the pass untouched.
    #[test]
    fn a_payload_that_is_not_a_pointer_is_left_for_the_arm_that_owns_it() {
        let fx = Inbox::new();
        fx.import(&sharer(), &sharer_enc());
        fx.post(&sharer(), b"not a share pointer", "claim-1");

        fx.pull();

        assert_eq!(fx.inbox_len(), 1);
    }

    /// A pointer whose `sharerPub` is not the contact that sent it is a bind
    /// failure, not staleness: it is reported as attributable abuse, and the
    /// item is never acked (AGENTS.md rule 6).
    #[test]
    fn a_pointer_that_does_not_bind_to_its_sender_is_reported_and_left_unacked() {
        let fx = Inbox::new();
        fx.import(&sharer(), &sharer_enc());
        let mut pointer = SharePointer::decode(&fx.pointer()).expect("our own pointer");
        pointer.sharer_identity_pk = stranger().verifying_key().to_sec1();
        fx.post(&sharer(), &pointer.encode(), "share-1");

        let events = fx.pull();

        assert!(fx.bookmarked().is_empty());
        assert_eq!(fx.inbox_len(), 1);
        assert!(
            matches!(events.as_slice(), [Event::AttributableAbuse { .. }]),
            "a bind failure is surfaced, never silent: {events:?}"
        );
    }

    /// Until-acked retention makes redelivery the transport's normal behaviour,
    /// so a second pass over an already-adopted share must not double-bookmark
    /// it, nor leave an item the anti-replay bar would refuse forever.
    #[test]
    fn a_redelivered_pointer_bookmarks_the_share_once() {
        let fx = Inbox::new();
        fx.import(&sharer(), &sharer_enc());
        fx.post(&sharer(), &fx.pointer(), "share-1");
        fx.pull();

        fx.post(&sharer(), &fx.pointer(), "share-2");
        fx.pull();

        assert_eq!(
            fx.bookmarked(),
            vec![SCOPE],
            "a re-accept bookmarks nothing new"
        );
        assert_eq!(fx.inbox_len(), 0, "and the redelivery is retired");
    }
}
