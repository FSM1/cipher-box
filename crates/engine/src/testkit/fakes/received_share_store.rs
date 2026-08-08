//! In-memory [`ReceivedShareStore`] fake — the durable received-shares
//! bookmark the grants accept flow persists before it acks.

use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use crate::grants::accept::StoredList;
use crate::grants::{ReceivedShareStore, ReceivedSharesList};
use crate::seams::{SeamError, SeamResult};

#[derive(Default)]
struct Inner {
    /// When set, every persist fails — models a durable-storage outage so a
    /// test can prove the accept flow does not ack on a persist failure.
    failing: bool,
    /// How many persists have succeeded — lets a test prove a durable write
    /// happened (or did not) around a self-healing re-accept.
    persists: u32,
    /// The persisted list as encoded bytes, so a reopen goes through the same
    /// codec a real backing does. Revision-free: a fake has one slot and no
    /// torn-write window to arbitrate.
    stored: Option<Zeroizing<Vec<u8>>>,
}

/// In-memory durable store for the recipient's received-shares list. Clones
/// share state ("reopen the same backing").
#[derive(Clone, Default)]
pub struct InMemoryReceivedShareStore {
    inner: Arc<Mutex<Inner>>,
}

impl InMemoryReceivedShareStore {
    /// Make every persist fail, or clear the failure.
    pub fn set_failing(&self, failing: bool) {
        self.inner.lock().expect("lock").failing = failing;
    }

    /// The number of persists that have succeeded.
    pub fn persist_count(&self) -> u32 {
        self.inner.lock().expect("lock").persists
    }
}

impl ReceivedShareStore for InMemoryReceivedShareStore {
    async fn persist(&self, shares: &ReceivedSharesList) -> SeamResult<()> {
        let encoded = StoredList::encode(shares, 1)
            .map_err(|e| SeamError::new(format!("received-shares encode failed: {e}")))?;
        let mut inner = self.inner.lock().expect("lock");
        if inner.failing {
            return Err(SeamError::new("received-share store offline"));
        }
        inner.persists += 1;
        inner.stored = Some(encoded);
        Ok(())
    }

    async fn load(&self) -> SeamResult<ReceivedSharesList> {
        let stored = self.inner.lock().expect("lock").stored.clone();
        match stored {
            None => Ok(ReceivedSharesList::new()),
            Some(bytes) => StoredList::decode(&bytes)
                .map(|stored| stored.shares)
                .map_err(|e| SeamError::new(format!("received-shares decode failed: {e}"))),
        }
    }
}
