//! Runtime helpers: timeout wrapper for blocking on the tokio runtime.

use std::time::Duration;

/// Timeout for network I/O in filesystem callbacks to prevent blocking the mount thread.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub(crate) const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);

/// Run an async future with a timeout on the tokio runtime.
/// Prevents filesystem thread hangs from indefinite network I/O.
#[cfg(any(feature = "fuse", feature = "winfsp"))]
pub fn block_with_timeout<F, T>(rt: &tokio::runtime::Handle, fut: F) -> Result<T, String>
where
    F: std::future::Future<Output = Result<T, String>>,
{
    rt.block_on(async {
        match tokio::time::timeout(NETWORK_TIMEOUT, fut).await {
            Ok(result) => result,
            Err(_) => Err("Operation timed out".to_string()),
        }
    })
}
