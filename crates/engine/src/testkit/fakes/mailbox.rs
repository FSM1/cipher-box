//! In-memory mailbox hub and per-recipient [`Mailbox`] fake.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::seams::{Mailbox, MailboxItem, SeamResult};

#[derive(Default)]
struct HubInner {
    next_id: u64,
    queues: HashMap<Vec<u8>, Vec<MailboxItem>>,
    seen_idempotency_keys: HashSet<(Vec<u8>, String)>,
}

/// The shared mailbox "server": routes posts between recipients so N
/// engines in a scenario exchange sealed blobs through one hub.
#[derive(Clone, Default)]
pub struct InMemoryMailboxHub {
    inner: Arc<Mutex<HubInner>>,
}

impl InMemoryMailboxHub {
    /// A [`Mailbox`] seam handle bound to one recipient's inbox.
    pub fn mailbox_for(&self, recipient_public_key: &[u8]) -> InMemoryMailbox {
        InMemoryMailbox {
            hub: self.clone(),
            recipient_public_key: recipient_public_key.to_vec(),
        }
    }
}

/// One account's view of the hub: posts route anywhere, polls and acks
/// operate on the bound recipient's own queue.
#[derive(Clone)]
pub struct InMemoryMailbox {
    hub: InMemoryMailboxHub,
    recipient_public_key: Vec<u8>,
}

impl Mailbox for InMemoryMailbox {
    async fn post(
        &self,
        recipient_public_key: &[u8],
        sealed_payload: &[u8],
        idempotency_key: &str,
    ) -> SeamResult<()> {
        let mut inner = self.hub.inner.lock().expect("lock");
        let dedupe_key = (recipient_public_key.to_vec(), idempotency_key.to_owned());
        if !inner.seen_idempotency_keys.insert(dedupe_key) {
            return Ok(());
        }
        inner.next_id += 1;
        let item = MailboxItem {
            item_id: format!("item-{}", inner.next_id),
            sealed_payload: sealed_payload.to_vec(),
        };
        inner
            .queues
            .entry(recipient_public_key.to_vec())
            .or_default()
            .push(item);
        Ok(())
    }

    async fn poll(&self) -> SeamResult<Vec<MailboxItem>> {
        Ok(self
            .hub
            .inner
            .lock()
            .expect("lock")
            .queues
            .get(&self.recipient_public_key)
            .cloned()
            .unwrap_or_default())
    }

    async fn ack(&self, item_id: &str) -> SeamResult<()> {
        if let Some(queue) = self
            .hub
            .inner
            .lock()
            .expect("lock")
            .queues
            .get_mut(&self.recipient_public_key)
        {
            queue.retain(|item| item.item_id != item_id);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::block_on;

    #[test]
    fn hub_routes_between_recipients_and_isolates_inboxes() {
        let hub = InMemoryMailboxHub::default();
        let alice = hub.mailbox_for(b"alice-pk");
        let bob = hub.mailbox_for(b"bob-pk");

        block_on(alice.post(b"bob-pk", b"sealed-for-bob", "k1")).unwrap();

        let bob_items = block_on(bob.poll()).unwrap();
        assert_eq!(bob_items.len(), 1);
        assert_eq!(bob_items[0].sealed_payload, b"sealed-for-bob");
        assert!(block_on(alice.poll()).unwrap().is_empty());
    }
}
