//! The `Mailbox` seam, refusing rather than pretending.
//!
//! The API's mailbox routes are bearer-authenticated, and the session bearer
//! lives inside the engine's own API client, which the facade hands no host.
//! Two ways out, both other slices: the engine speaks these routes through that
//! client (blueprint/engine.md gives both platforms as "the engine's own API
//! client"), or a host seam is given a credential of its own. A transport
//! written here now would 401 on every call, and its wire would be a fourth
//! copy of `crates/engine/src/api/client.rs`'s.
//!
//! So this refuses in as many words. The engine reaches no mailbox path yet, so
//! nothing calls it — and when something does, it says why rather than handing
//! back an opaque status.

use cipherbox_engine::seams::{Mailbox, MailboxItem, SeamError, SeamResult};

const UNWIRED: &str = "mailbox delivery needs a session credential this host is not given";

/// The unwired mailbox seam.
pub struct UnwiredMailbox;

impl Mailbox for UnwiredMailbox {
    async fn post(
        &self,
        _recipient_public_key: &[u8],
        _sealed_payload: &[u8],
        _idempotency_key: &str,
    ) -> SeamResult<()> {
        Err(SeamError::new(UNWIRED))
    }

    /// Fails rather than answering empty: an inbox nobody can read is not an
    /// inbox with nothing in it, and a silent empty poll drops a grant.
    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        Err(SeamError::new(UNWIRED))
    }

    async fn ack(&self, _item_id: &str) -> SeamResult<()> {
        Err(SeamError::new(UNWIRED))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every arm refuses, and the poll arm refuses rather than reporting an
    /// empty inbox — the one that would otherwise fail open.
    #[tokio::test]
    async fn every_arm_refuses_until_a_credential_exists() {
        assert!(
            UnwiredMailbox
                .post(&[7u8; 33], b"sealed", "key")
                .await
                .is_err()
        );
        assert!(UnwiredMailbox.ack("item").await.is_err());
        assert!(
            UnwiredMailbox.poll().await.is_err(),
            "an unreadable inbox is not an empty one",
        );
    }
}
