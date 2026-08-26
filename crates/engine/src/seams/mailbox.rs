//! `Mailbox` — sealed-blob discovery transport (blueprint/engine.md).

use super::SeamResult;

/// The RFC 3986 unreserved alphabet, 1-128 characters — the shape the API's
/// `PostMessageDto` fixes for an idempotency key, and the shape [`Mailbox`]
/// requires of an `item_id`.
///
/// It is deliberately URL-path-safe: an id outside it cannot be interpolated
/// into an authenticated route without steering it.
pub(crate) fn is_unreserved_1_128(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
}

/// Whether `item_id` is one [`Mailbox::ack`] can carry, per the trait contract.
///
/// Beyond the alphabet: the two dot segments are excluded because URL parsers
/// resolve them away, so an id of `.` or `..` would move the ack to a different
/// route rather than name an item.
pub(crate) fn item_id_is_legal(item_id: &str) -> bool {
    is_unreserved_1_128(item_id) && item_id != "." && item_id != ".."
}

/// One pending mailbox item, as delivered by [`Mailbox::poll`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxItem {
    /// Transport-assigned identifier, used to ack. Legal ids are 1-128 RFC
    /// 3986 unreserved characters and neither dot segment; the engine drops an
    /// item it could never ack.
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
/// - **Wire shape**: `recipient_public_key` is the recipient's compressed SEC1
///   secp256k1 **identity** key (33 bytes) — the account the transport resolves
///   an inbox from, never the X25519 subkey the payload is sealed to
///   (blueprint/api.md "Mailbox"). `sealed_payload` is at most 8 KiB and
///   `idempotency_key` is 1-128 RFC 3986 unreserved characters, both as the
///   API's `PostMessageDto` fixes them.
/// - **Item ids**: an `item_id` is 1-128 RFC 3986 unreserved characters and
///   neither dot segment, so [`Mailbox::ack`] can always name it in a URL path
///   ([`item_id_is_legal`]).
///
/// Not a host seam: every mailbox route is JWT-guarded, and the access bearer
/// never leaves the engine. v2.0 therefore rides the API mailbox through the
/// engine's own [`ApiClient`](crate::api::ApiClient) on both platforms, which
/// is where the token and its refresh already live; a decentralized inbox stays
/// swappable behind this trait (#25 D2).
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
