//! [`Mailbox`] over the engine's own API client.
//!
//! Riding [`ApiClient`] gives the mailbox the same single-flight refresh and
//! one-retry-on-401 as every other authed call, from the one token store there
//! is; see the trait for why this is not a host seam.

use cipherbox_core::hex::lower as hex_lower;

use super::ApiClient;
use crate::seams::{CredentialStore, Http, Mailbox, MailboxItem, SeamError, SeamResult};

impl<H: Http, C: CredentialStore> Mailbox for ApiClient<H, C> {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        self.mailbox_post(
            &hex_lower(recipient_public_key),
            sealed_payload,
            idempotency_key,
        )
        .await
        .map(drop)
        .map_err(|error| SeamError::new(format!("mailbox post: {error}")))
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        Ok(self
            .mailbox_poll()
            .await
            .map_err(|error| SeamError::new(format!("mailbox poll: {error}")))?
            .into_iter()
            .map(|item| MailboxItem {
                item_id: item.id,
                sealed_payload: item.blob,
            })
            .collect())
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        self.mailbox_ack(item_id)
            .await
            .map_err(|error| SeamError::new(format!("mailbox ack: {error}")))
    }
}
