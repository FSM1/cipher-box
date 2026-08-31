//! Mailbox logic — sealed discovery/courtesy traffic over the [`Mailbox`] seam
//! (blueprint/engine.md "Mailbox logic", #34 D5, #39 D9).
//!
//! The mailbox is the API's integrity-*untrusted* transport: anyone can HPKE-
//! seal to a recipient's encryption subkey, so all trust comes from the sender
//! signature carried **inside** the seal, verified against the contact-code-
//! anchored identity key. This module composes `crates/core`'s
//! [`seal_mailbox_payload`]/[`open_mailbox_payload`] with the seam; it holds no
//! crypto of its own.
//!
//! Two invariants this module enforces (the rest — resolve, adoption gate,
//! durable append — is the [`grants`](crate::grants) accept flow):
//!
//! - **Drop-before-resolve**: [`poll_verified`] opens and sender-verifies every
//!   polled item and returns only the authenticated ones. An item that fails to
//!   open (tamper, wrong recipient, version downgrade) or whose sender signature
//!   does not verify is dropped, never surfaced — so no forged item ever costs a
//!   wasted name resolve.
//! - **Ack-after-durable**: the accept flow calls the [`Mailbox`] seam's `ack`
//!   **only** after the pointed-at fact is durably recorded (the share appended
//!   to the vault list, the re-point applied); until-acked retention then
//!   guarantees at-least-once delivery.

use cipherbox_core::payload::{open_mailbox_payload, seal_mailbox_payload};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::seams::{
    Mailbox, MailboxItem, SeamError, SeamResult, is_unreserved_1_128, item_id_is_legal,
};

/// The transport's sealed-payload bound (API `PostMessageDto`).
const MAX_SEALED_BYTES: usize = 8192;

/// The transport's idempotency-key alphabet and bound (API `PostMessageDto`).
pub(crate) fn idempotency_key_is_legal(key: &str) -> bool {
    is_unreserved_1_128(key)
}

/// An opened, sender-authenticated mailbox item: the transport id needed to
/// [`ack`], the verified sender identity to anchor against a contact, and the
/// opaque application payload (a share pointer, an invite claim — the
/// [`grants`](crate::grants) layer frames its meaning).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMailboxItem {
    /// The transport-assigned id, used to [`ack`] once the fact is durable.
    pub item_id: String,
    /// The verified sender identity key — anchor it against the contact code
    /// before trusting the payload's authorship.
    pub sender_identity: EcdsaVerifier,
    /// The opaque application payload.
    pub payload: Vec<u8>,
}

/// Seal `payload` to `recipient_enc_pub` (sender-signed inside the seal) and
/// post it to `recipient_identity`'s inbox with a sender-supplied idempotency
/// key. `ephemeral_scalar` is injected, fresh-per-call HPKE entropy (reuse under
/// one recipient is a catastrophic break — the caller sources it from the
/// entropy input, never a clock or a constant).
///
/// Routing and sealing use *different* keys: the [`Mailbox`] seam addresses on
/// the recipient's secp256k1 identity key, the seal targets their X25519
/// encryption subkey (see [`Mailbox`] for the wire shape it enforces).
#[allow(clippy::too_many_arguments)]
pub async fn post_sealed<M: Mailbox>(
    mailbox: &M,
    recipient_enc_pub: &X25519Public,
    recipient_identity: &EcdsaVerifier,
    ephemeral_scalar: &[u8; 32],
    v: u64,
    sender_signer: &EcdsaSigner,
    payload: &[u8],
    idempotency_key: &str,
) -> SeamResult<()> {
    if !idempotency_key_is_legal(idempotency_key) {
        return Err(SeamError::new(
            "idempotency key must be 1-128 unreserved characters",
        ));
    }
    let sealed = seal_mailbox_payload(
        recipient_enc_pub,
        ephemeral_scalar,
        v,
        sender_signer,
        payload,
    );
    if sealed.len() > MAX_SEALED_BYTES {
        return Err(SeamError::new("sealed payload exceeds the transport bound"));
    }
    mailbox
        .post(&recipient_identity.to_sec1(), &sealed, idempotency_key)
        .await
}

/// Poll the inbox and return only the sender-authenticated items.
///
/// Every polled blob is HPKE-opened under `my_enc_secret` and its inner sender
/// signature verified (both inside core's [`open_mailbox_payload`]). An item
/// that does not open or does not verify is an unauthenticated item and is
/// **dropped** — excluded from the result and left for the transport's TTL to
/// reap — so a forged blob never triggers a wasted resolve. Authenticated items
/// preserve poll order.
pub async fn poll_verified<M: Mailbox>(
    mailbox: &M,
    my_enc_secret: &X25519Secret,
    v: u64,
) -> SeamResult<Vec<VerifiedMailboxItem>> {
    Ok(mailbox
        .poll()
        .await?
        .into_iter()
        .filter_map(|item| verified(my_enc_secret, v, item))
        .collect())
}

/// Open and sender-verify one polled item, or drop it.
///
/// A failed open/verify is a fail-closed drop, never an error that stalls the
/// poll: one hostile blob must not deny delivery of the honest ones. An id the
/// transport contract does not admit is dropped for the same reason and one
/// more: the engine could never ack it, so acting on it would earn a
/// redelivery on every later pass.
fn verified(
    my_enc_secret: &X25519Secret,
    v: u64,
    item: MailboxItem,
) -> Option<VerifiedMailboxItem> {
    if !item_id_is_legal(&item.item_id) {
        return None;
    }
    let opened = open_mailbox_payload(my_enc_secret, v, &item.sealed_payload).ok()?;
    Some(VerifiedMailboxItem {
        item_id: item.item_id,
        sender_identity: opened.sender_identity,
        payload: opened.payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;
    use crate::testkit::fakes::InMemoryMailboxHub;

    const V: u64 = 2;

    fn sender() -> EcdsaSigner {
        EcdsaSigner::from_scalar(&[0x22; 32]).expect("valid scalar")
    }

    fn recipient() -> X25519Secret {
        X25519Secret::from_scalar([0x40; 32])
    }

    fn recipient_identity() -> EcdsaVerifier {
        EcdsaSigner::from_scalar(&[0x41; 32])
            .expect("valid scalar")
            .verifying_key()
    }

    #[test]
    fn post_then_poll_round_trips_a_verified_item() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let address = recipient_identity().to_sec1();
        let sender_box = hub.mailbox_for(b"sender-inbox");
        let recip_box = hub.mailbox_for(&address);

        block_on(post_sealed(
            &sender_box,
            &recip.public(),
            &recipient_identity(),
            &[0x51; 32],
            V,
            &sender(),
            b"share-pointer",
            "idem-1",
        ))
        .unwrap();

        let items = block_on(poll_verified(&recip_box, &recip, V)).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].payload, b"share-pointer");
        assert_eq!(items[0].sender_identity, sender().verifying_key());
    }

    #[test]
    fn unauthenticated_items_are_dropped_before_resolve() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let address = recipient_identity().to_sec1();
        let recip_box = hub.mailbox_for(&address);
        let poster = hub.mailbox_for(b"poster");

        // Junk that never opens, and an item sealed to a DIFFERENT recipient
        // (wrong-recipient HPKE open failure): both are unauthenticated.
        block_on(poster.post(&address, b"not a sealed block", "junk")).unwrap();
        let other = X25519Secret::from_scalar([0x99; 32]);
        block_on(post_sealed(
            &poster,
            &other.public(),
            &recipient_identity(),
            &[0x52; 32],
            V,
            &sender(),
            b"misaddressed",
            "misaddr",
        ))
        .unwrap();

        let items = block_on(poll_verified(&recip_box, &recip, V)).unwrap();
        assert!(items.is_empty(), "no forged item survives to a resolve");
    }

    /// A hostile transport can choose the id it hands back. An id the engine
    /// could never ack is dropped at ingest, so no flow acts on an item that
    /// would then be redelivered forever.
    #[test]
    fn an_item_the_engine_could_never_ack_is_dropped() {
        /// Hands back one honestly-sealed item under a caller-chosen id.
        struct IdChoosingMailbox(String, Vec<u8>);

        impl Mailbox for IdChoosingMailbox {
            async fn post(&self, _: &[u8], _: &[u8], _: &str) -> SeamResult<()> {
                Ok(())
            }
            async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
                Ok(vec![MailboxItem {
                    item_id: self.0.clone(),
                    sealed_payload: self.1.clone(),
                }])
            }
            async fn ack(&self, _: &str) -> SeamResult<()> {
                Ok(())
            }
        }

        let recip = recipient();
        let sealed = seal_mailbox_payload(&recip.public(), &[0x56; 32], V, &sender(), b"pointer");

        for illegal in ["..", ".", "m1/../account", "m 1", ""] {
            let mailbox = IdChoosingMailbox(illegal.to_owned(), sealed.clone());
            assert!(
                block_on(poll_verified(&mailbox, &recip, V))
                    .unwrap()
                    .is_empty(),
                "{illegal:?} must not survive to a flow that would ack it"
            );
        }

        let mailbox = IdChoosingMailbox("0b7f5a2e-1c3d".to_owned(), sealed);
        assert_eq!(
            block_on(poll_verified(&mailbox, &recip, V)).unwrap().len(),
            1,
            "a legal id still delivers"
        );
    }

    #[test]
    fn routing_addresses_the_identity_key_not_the_seal_target() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let poster = hub.mailbox_for(b"poster");

        block_on(post_sealed(
            &poster,
            &recip.public(),
            &recipient_identity(),
            &[0x54; 32],
            V,
            &sender(),
            b"p",
            "idem",
        ))
        .unwrap();

        assert!(
            block_on(hub.mailbox_for(&recip.public().to_bytes()).poll())
                .unwrap()
                .is_empty(),
            "the encryption subkey addresses no inbox"
        );
        assert_eq!(
            block_on(hub.mailbox_for(&recipient_identity().to_sec1()).poll())
                .unwrap()
                .len(),
            1,
            "the identity key is the routing address"
        );
    }

    #[test]
    fn a_post_the_transport_would_reject_never_leaves_the_produce_site() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let identity = recipient_identity();
        let poster = hub.mailbox_for(b"poster");

        let post = |payload: &[u8], idempotency_key: &str| {
            block_on(post_sealed(
                &poster,
                &recip.public(),
                &identity,
                &[0x55; 32],
                V,
                &sender(),
                payload,
                idempotency_key,
            ))
        };

        for illegal in ["grant:abc", "", &"k".repeat(129), "a b", "a/b", "é"] {
            assert!(
                post(b"p", illegal).is_err(),
                "{illegal:?} must not reach the transport"
            );
        }
        assert!(
            post(&vec![0u8; MAX_SEALED_BYTES], "idem").is_err(),
            "a payload sealing past the transport bound must not be posted"
        );

        assert!(
            block_on(hub.mailbox_for(&identity.to_sec1()).poll())
                .unwrap()
                .is_empty(),
            "a refused post delivers nothing"
        );
    }

    #[test]
    fn ack_removes_only_after_the_call() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let address = recipient_identity().to_sec1();
        let recip_box = hub.mailbox_for(&address);
        let poster = hub.mailbox_for(b"poster");

        block_on(post_sealed(
            &poster,
            &recip.public(),
            &recipient_identity(),
            &[0x53; 32],
            V,
            &sender(),
            b"p",
            "idem",
        ))
        .unwrap();

        let items = block_on(poll_verified(&recip_box, &recip, V)).unwrap();
        assert_eq!(items.len(), 1, "item is retained until acked");
        block_on(recip_box.ack(&items[0].item_id)).unwrap();
        assert!(
            block_on(poll_verified(&recip_box, &recip, V))
                .unwrap()
                .is_empty(),
            "ack deletes the item"
        );
    }
}
