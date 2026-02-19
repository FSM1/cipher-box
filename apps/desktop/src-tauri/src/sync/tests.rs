//! Unit tests for the offline write queue.
//!
//! Uses a mock UploadHandler that can be configured to succeed or fail.

#[cfg(test)]
mod write_queue_tests {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use crate::sync::queue::{QueuedWrite, UploadHandler, WriteQueue};

    // ── Mock Upload Handler ──────────────────────────────────────────────

    /// Mock handler that always succeeds.
    struct SuccessHandler {
        call_count: AtomicU32,
    }

    impl SuccessHandler {
        fn new() -> Self {
            Self {
                call_count: AtomicU32::new(0),
            }
        }

        fn calls(&self) -> u32 {
            self.call_count.load(Ordering::SeqCst)
        }
    }

    impl UploadHandler for SuccessHandler {
        async fn upload_and_register(
            &self,
            _write: &QueuedWrite,
        ) -> Result<(), String> {
            self.call_count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// Mock handler that always fails with a configurable message.
    struct FailHandler;

    impl UploadHandler for FailHandler {
        async fn upload_and_register(
            &self,
            _write: &QueuedWrite,
        ) -> Result<(), String> {
            Err("network unreachable".to_string())
        }
    }

    /// Mock handler that tracks the order of processed filenames.
    struct OrderTracker {
        order: std::sync::Mutex<Vec<String>>,
    }

    impl OrderTracker {
        fn new() -> Self {
            Self {
                order: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn processed_order(&self) -> Vec<String> {
            self.order.lock().unwrap().clone()
        }
    }

    impl UploadHandler for OrderTracker {
        async fn upload_and_register(
            &self,
            write: &QueuedWrite,
        ) -> Result<(), String> {
            self.order.lock().unwrap().push(write.filename.clone());
            Ok(())
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    fn make_write(id: &str, filename: &str) -> QueuedWrite {
        QueuedWrite {
            id: id.to_string(),
            parent_ino: 1,
            encrypted_content: vec![0xDE, 0xAD],
            encrypted_file_key: vec![0xBE, 0xEF],
            iv: vec![0x00; 12],
            filename: filename.to_string(),
            created_at: Instant::now(),
            retries: 0,
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_write_queue_enqueue_and_len() {
        let mut queue = WriteQueue::new(5);
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());

        queue.enqueue(make_write("1", "a.txt"));
        assert_eq!(queue.len(), 1);
        assert!(!queue.is_empty());

        queue.enqueue(make_write("2", "b.txt"));
        assert_eq!(queue.len(), 2);

        queue.enqueue(make_write("3", "c.txt"));
        assert_eq!(queue.len(), 3);
    }

    #[tokio::test]
    async fn test_write_queue_process_success() {
        let mut queue = WriteQueue::new(5);
        queue.enqueue(make_write("1", "a.txt"));
        queue.enqueue(make_write("2", "b.txt"));

        let handler = SuccessHandler::new();
        let processed = queue.process(&handler).await.unwrap();

        assert_eq!(processed, 2);
        assert_eq!(handler.calls(), 2);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn test_write_queue_process_failure_retries() {
        let mut queue = WriteQueue::new(3); // max 3 retries
        queue.enqueue(make_write("1", "failing.txt"));

        let handler = FailHandler;

        // First process: item fails, retries=1, moved to back
        let processed = queue.process(&handler).await.unwrap();
        assert_eq!(processed, 0);
        assert_eq!(queue.len(), 1); // Still in queue

        // Second process: retries=2
        let _ = queue.process(&handler).await;
        assert_eq!(queue.len(), 1);

        // Third process: retries=3
        let _ = queue.process(&handler).await;
        assert_eq!(queue.len(), 1);

        // Fourth process: retries=4 > max_retries=3, item dropped
        let _ = queue.process(&handler).await;
        assert_eq!(queue.len(), 0);
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn test_write_queue_fifo_order() {
        let mut queue = WriteQueue::new(5);
        queue.enqueue(make_write("1", "first.txt"));
        queue.enqueue(make_write("2", "second.txt"));
        queue.enqueue(make_write("3", "third.txt"));

        let tracker = OrderTracker::new();
        let processed = queue.process(&tracker).await.unwrap();

        assert_eq!(processed, 3);
        assert_eq!(
            tracker.processed_order(),
            vec!["first.txt", "second.txt", "third.txt"]
        );
    }

    #[tokio::test]
    async fn test_write_queue_is_empty() {
        let mut queue = WriteQueue::new(5);

        // Empty on init
        assert!(queue.is_empty());

        // Non-empty after enqueue
        queue.enqueue(make_write("1", "test.txt"));
        assert!(!queue.is_empty());

        // Empty after successful process
        let handler = SuccessHandler::new();
        let _ = queue.process(&handler).await;
        assert!(queue.is_empty());
    }

    #[tokio::test]
    async fn test_write_queue_process_empty_returns_zero() {
        let mut queue = WriteQueue::new(5);
        let handler = SuccessHandler::new();
        let processed = queue.process(&handler).await.unwrap();
        assert_eq!(processed, 0);
        assert_eq!(handler.calls(), 0);
    }

    #[tokio::test]
    async fn test_write_queue_default_max_retries() {
        let queue = WriteQueue::default();
        assert!(queue.is_empty());
        // Default max_retries is 5 -- we verify by creating with default
        // and checking an item gets 5 retries before drop
        let mut queue = WriteQueue::default();
        queue.enqueue(make_write("1", "test.txt"));

        let handler = FailHandler;
        for _ in 0..5 {
            let _ = queue.process(&handler).await;
            assert_eq!(queue.len(), 1, "Item should remain in queue within max_retries");
        }
        // 6th failure: retries=6 > max_retries=5, dropped
        let _ = queue.process(&handler).await;
        assert!(queue.is_empty(), "Item should be dropped after exceeding max_retries");
    }
}
