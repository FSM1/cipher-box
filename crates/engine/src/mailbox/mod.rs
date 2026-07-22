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
//! - **Ack-after-durable**: [`ack`] is a thin, intention-revealing passthrough.
//!   The engine calls it **only** after the pointed-at fact is durably recorded
//!   (the share appended to the vault list, the re-point applied); until-acked
//!   retention then guarantees at-least-once delivery.

use cipherbox_core::payload::{open_mailbox_payload, seal_mailbox_payload};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::x25519::{X25519Public, X25519Secret};

use crate::seams::{Mailbox, SeamResult};

/// An opened, sender-authenticated mailbox item: the transport id needed to
/// [`ack`], the verified sender identity to anchor against a contact, and the
/// opaque application payload (a share pointer, a re-point accelerator, an
/// invite claim — the [`grants`](crate::grants) layer frames its meaning).
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
/// post it to `recipient_address`'s inbox with a sender-supplied idempotency
/// key. `ephemeral_scalar` is injected, fresh-per-call HPKE entropy (reuse under
/// one recipient is a catastrophic break — the caller sources it from the
/// entropy input, never a clock or a constant).
///
/// `recipient_address` is the opaque pubkey the [`Mailbox`] seam routes on; in
/// v2.0 that is the recipient's encryption-subkey public bytes, i.e. the same
/// key `payload` is sealed to.
#[allow(clippy::too_many_arguments)]
pub async fn post_sealed<M: Mailbox>(
    mailbox: &M,
    recipient_enc_pub: &X25519Public,
    recipient_address: &[u8],
    ephemeral_scalar: &[u8; 32],
    v: u64,
    sender_signer: &EcdsaSigner,
    payload: &[u8],
    idempotency_key: &str,
) -> SeamResult<()> {
    let sealed = seal_mailbox_payload(
        recipient_enc_pub,
        ephemeral_scalar,
        v,
        sender_signer,
        payload,
    );
    mailbox
        .post(recipient_address, &sealed, idempotency_key)
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
    let pending = mailbox.poll().await?;
    let mut verified = Vec::new();
    for item in pending {
        // A failed open/verify is a fail-closed drop, never an error that stalls
        // the poll: one hostile blob must not deny delivery of the honest ones.
        if let Ok(opened) = open_mailbox_payload(my_enc_secret, v, &item.sealed_payload) {
            verified.push(VerifiedMailboxItem {
                item_id: item.item_id,
                sender_identity: opened.sender_identity,
                payload: opened.payload,
            });
        }
    }
    Ok(verified)
}

/// Acknowledge (delete) an item — call this **only** after the pointed-at fact
/// is durably recorded. A thin passthrough that names the ack-after-durable
/// contract at its one call boundary; until-acked retention makes premature
/// acking the only way to lose a share, so the accept flow acks last.
pub async fn ack<M: Mailbox>(mailbox: &M, item_id: &str) -> SeamResult<()> {
    mailbox.ack(item_id).await
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

    #[test]
    fn post_then_poll_round_trips_a_verified_item() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let address = recip.public().to_bytes();
        let sender_box = hub.mailbox_for(b"sender-inbox");
        let recip_box = hub.mailbox_for(&address);

        block_on(post_sealed(
            &sender_box,
            &recip.public(),
            &address,
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
        let address = recip.public().to_bytes();
        let recip_box = hub.mailbox_for(&address);
        let poster = hub.mailbox_for(b"poster");

        // Junk that never opens, and an item sealed to a DIFFERENT recipient
        // (wrong-recipient HPKE open failure): both are unauthenticated.
        block_on(poster.post(&address, b"not a sealed block", "junk")).unwrap();
        let other = X25519Secret::from_scalar([0x99; 32]);
        block_on(post_sealed(
            &poster,
            &other.public(),
            &address,
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

    #[test]
    fn ack_removes_only_after_the_call() {
        let hub = InMemoryMailboxHub::default();
        let recip = recipient();
        let address = recip.public().to_bytes();
        let recip_box = hub.mailbox_for(&address);
        let poster = hub.mailbox_for(b"poster");

        block_on(post_sealed(
            &poster,
            &recip.public(),
            &address,
            &[0x53; 32],
            V,
            &sender(),
            b"p",
            "idem",
        ))
        .unwrap();

        let items = block_on(poll_verified(&recip_box, &recip, V)).unwrap();
        assert_eq!(items.len(), 1, "item is retained until acked");
        block_on(ack(&recip_box, &items[0].item_id)).unwrap();
        assert!(
            block_on(poll_verified(&recip_box, &recip, V))
                .unwrap()
                .is_empty(),
            "ack deletes the item"
        );
    }
}
