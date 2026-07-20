//! `Mailbox` — sealed-blob discovery transport (blueprint/engine.md).

use super::SeamResult;

/// One pending mailbox item, as delivered by [`Mailbox::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxItem {
    /// Transport-assigned identifier, used to ack.
    pub item_id: String,
    /// The sealed payload, opaque to the transport. Sender authentication
    /// lives inside the seal and is verified by the engine (#39 D9).
    pub sealed_payload: Vec<u8>,
}

/// Post/poll/ack of sealed blobs to/from a recipient public key.
///
/// An integrity-untrusted transport for discovery and courtesy traffic only
/// (share pointers, re-point accelerators, invite claims) — nothing on it is
/// load-bearing for safety. One instance is bound to one account's inbox:
/// [`Mailbox::poll`] reads the caller's own items. Contract, enforced by the
/// conformance kit:
///
/// - **Until-acked retention**: an item stays visible to `poll` until acked;
///   ack deletes, and acking is idempotent.
/// - **Idempotent post**: re-posting with an already-seen idempotency key
///   for the same recipient creates no second item.
///
/// v2.0 rides the API mailbox via the engine's own API client on both
/// platforms; a decentralized inbox stays swappable behind this trait
/// (#25 D2).
pub trait Mailbox {
    /// Posts a sealed payload to a recipient's inbox.
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()>;

    /// All items currently pending in the caller's own inbox.
    async fn poll(&self) -> SeamResult<Vec<MailboxItem>>;

    /// Acknowledges (deletes) one item. Idempotent: acking an already-acked
    /// or unknown item succeeds.
    ///
    /// The engine acks only after the pointed-at fact is durably recorded
    /// (blueprint/engine.md "Mailbox logic").
    async fn ack(&self, item_id: &str) -> SeamResult<()>;
}
