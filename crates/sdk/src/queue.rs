//! Offline write queue for deferred file uploads.
//!
//! When the user writes a file while offline (or when the network drops),
//! the encrypted content is queued in memory and retried when connectivity returns.
//!
//! Memory-only queue per CONTEXT.md -- queued items are lost on app quit.
//! Acceptable for v1 given small file sizes and tech demo scope.

use std::collections::VecDeque;
use std::time::Instant;

/// A single queued write operation (already encrypted at queue time).
#[derive(Debug, Clone)]
pub struct QueuedWrite {
    /// Unique identifier for this queued item.
    pub id: String,
    /// Parent folder inode number (for folder metadata rebuild).
    pub parent_ino: u64,
    /// Already-encrypted file content (AES-256-GCM sealed bytes).
    pub encrypted_content: Vec<u8>,
    /// ECIES-wrapped file key (hex-encoded).
    pub encrypted_file_key: Vec<u8>,
    /// AES-GCM initialization vector.
    pub iv: Vec<u8>,
    /// Original filename.
    pub filename: String,
    /// When this write was queued.
    pub created_at: Instant,
    /// Number of upload attempts that failed.
    pub retries: u32,
}

/// Trait abstracting the upload operation for testability.
///
/// In production, `ApiClient` implements this via IPFS upload + folder metadata update.
/// In tests, a mock implementation controls success/failure behavior.
#[allow(async_fn_in_trait)]
pub trait UploadHandler {
    /// Attempt to upload encrypted content and update the parent folder metadata.
    ///
    /// Returns `Ok(())` on success, `Err(message)` on failure.
    async fn upload_and_register(
        &self,
        write: &QueuedWrite,
    ) -> Result<(), String>;
}

/// FIFO queue of offline writes awaiting upload.
///
/// Items are processed front-to-back. On failure, the item is moved to the
/// back with `retries` incremented. Items exceeding `max_retries` are dropped.
pub struct WriteQueue {
    queue: VecDeque<QueuedWrite>,
    max_retries: u32,
}

impl WriteQueue {
    /// Create a new empty write queue with the given max retry count.
    pub fn new(max_retries: u32) -> Self {
        Self {
            queue: VecDeque::new(),
            max_retries,
        }
    }

    /// Add a write operation to the back of the queue.
    pub fn enqueue(&mut self, write: QueuedWrite) {
        self.queue.push_back(write);
    }

    /// Process all queued writes using the given upload handler.
    ///
    /// Returns the number of successfully processed items.
    /// Items that fail are moved to the back of the queue with `retries` incremented.
    /// Items exceeding `max_retries` are dropped with a log message.
    pub async fn process<H: UploadHandler>(&mut self, handler: &H) -> Result<usize, String> {
        let count = self.queue.len();
        if count == 0 {
            return Ok(0);
        }

        let mut processed = 0;
        let mut remaining = VecDeque::new();

        // Process each item exactly once per call
        while let Some(mut item) = self.queue.pop_front() {
            match handler.upload_and_register(&item).await {
                Ok(()) => {
                    log::info!(
                        "Queued write processed: {} ({})",
                        item.filename,
                        item.id
                    );
                    processed += 1;
                }
                Err(e) => {
                    item.retries += 1;
                    if item.retries > self.max_retries {
                        log::error!(
                            "Queued write dropped after {} retries: {} ({}) - {}",
                            self.max_retries,
                            item.filename,
                            item.id,
                            e
                        );
                    } else {
                        log::warn!(
                            "Queued write retry {}/{}: {} ({}) - {}",
                            item.retries,
                            self.max_retries,
                            item.filename,
                            item.id,
                            e
                        );
                        remaining.push_back(item);
                    }
                }
            }
        }

        self.queue = remaining;
        Ok(processed)
    }

    /// Number of items currently in the queue.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

impl Default for WriteQueue {
    fn default() -> Self {
        Self::new(5)
    }
}
