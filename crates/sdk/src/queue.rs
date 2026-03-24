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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a QueuedWrite with minimal boilerplate.
    fn make_write(id: &str, filename: &str) -> QueuedWrite {
        QueuedWrite {
            id: id.to_string(),
            parent_ino: 1,
            encrypted_content: vec![0xAA, 0xBB],
            encrypted_file_key: vec![0xCC],
            iv: vec![0xDD],
            filename: filename.to_string(),
            created_at: Instant::now(),
            retries: 0,
        }
    }

    #[test]
    fn new_creates_empty_queue() {
        let q = WriteQueue::new(3);
        assert_eq!(q.len(), 0);
        assert!(q.is_empty());
    }

    #[test]
    fn enqueue_adds_items_and_len_reflects_count() {
        let mut q = WriteQueue::new(3);
        q.enqueue(make_write("a", "file_a.txt"));
        assert_eq!(q.len(), 1);
        assert!(!q.is_empty());

        q.enqueue(make_write("b", "file_b.txt"));
        assert_eq!(q.len(), 2);

        q.enqueue(make_write("c", "file_c.txt"));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn is_empty_returns_correct_values() {
        let mut q = WriteQueue::new(3);
        assert!(q.is_empty());

        q.enqueue(make_write("x", "x.txt"));
        assert!(!q.is_empty());
    }

    #[test]
    fn default_creates_queue_with_max_retries_5() {
        let q = WriteQueue::default();
        assert!(q.is_empty());
        // Verify max_retries is 5 by checking the field directly.
        assert_eq!(q.max_retries, 5);
    }

    // ---- Async tests using a mock UploadHandler ----

    /// Mock handler that always succeeds.
    struct AlwaysOk;
    impl UploadHandler for AlwaysOk {
        async fn upload_and_register(&self, _write: &QueuedWrite) -> Result<(), String> {
            Ok(())
        }
    }

    /// Mock handler that always fails with a message.
    struct AlwaysFail;
    impl UploadHandler for AlwaysFail {
        async fn upload_and_register(&self, _write: &QueuedWrite) -> Result<(), String> {
            Err("network down".to_string())
        }
    }

    #[tokio::test]
    async fn process_dequeues_in_fifo_order() {
        // Use a handler that records the order items are processed.
        use std::sync::Mutex;
        struct OrderTracker(Mutex<Vec<String>>);
        impl UploadHandler for OrderTracker {
            async fn upload_and_register(&self, write: &QueuedWrite) -> Result<(), String> {
                self.0.lock().unwrap().push(write.id.clone());
                Ok(())
            }
        }

        let tracker = OrderTracker(Mutex::new(Vec::new()));
        let mut q = WriteQueue::new(3);
        q.enqueue(make_write("first", "1.txt"));
        q.enqueue(make_write("second", "2.txt"));
        q.enqueue(make_write("third", "3.txt"));

        let processed = q.process(&tracker).await.unwrap();
        assert_eq!(processed, 3);
        assert!(q.is_empty());

        let order = tracker.0.lock().unwrap();
        assert_eq!(*order, vec!["first", "second", "third"]);
    }

    #[tokio::test]
    async fn process_success_removes_items() {
        let mut q = WriteQueue::new(3);
        q.enqueue(make_write("a", "a.txt"));
        q.enqueue(make_write("b", "b.txt"));

        let processed = q.process(&AlwaysOk).await.unwrap();
        assert_eq!(processed, 2);
        assert_eq!(q.len(), 0);
    }

    #[tokio::test]
    async fn process_failure_increments_retries_and_requeues() {
        let mut q = WriteQueue::new(3);
        q.enqueue(make_write("a", "a.txt"));

        // First process: fails, retries goes 0 -> 1, item requeued.
        let processed = q.process(&AlwaysFail).await.unwrap();
        assert_eq!(processed, 0);
        assert_eq!(q.len(), 1);

        // Second process: fails again, retries goes 1 -> 2.
        let _ = q.process(&AlwaysFail).await.unwrap();
        assert_eq!(q.len(), 1);

        // Third process: fails, retries goes 2 -> 3.
        let _ = q.process(&AlwaysFail).await.unwrap();
        assert_eq!(q.len(), 1);

        // Fourth process: retries goes 3 -> 4, exceeds max_retries=3, item dropped.
        let _ = q.process(&AlwaysFail).await.unwrap();
        assert_eq!(q.len(), 0);
    }

    #[tokio::test]
    async fn process_empty_queue_returns_zero() {
        let mut q = WriteQueue::new(3);
        let processed = q.process(&AlwaysOk).await.unwrap();
        assert_eq!(processed, 0);
    }
}
