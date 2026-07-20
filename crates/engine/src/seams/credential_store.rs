//! `CredentialStore` — refresh-token persistence (blueprint/engine.md).

use super::SeamResult;

/// Refresh-token persistence.
///
/// The rotating refresh token persists per platform: OS keychain on
/// desktop; a **no-op** on web, where the HTTP-only cookie rides the
/// [`super::Http`] seam instead. The no-op is contractual, so persistence
/// is best-effort: `load` after `store` returns either the stored token or
/// `None` — never a different token — and `clear` always results in `None`.
/// The short-lived access JWT never touches this seam (engine memory only).
pub trait CredentialStore {
    /// Persists the refresh token, replacing any previous one. A no-op
    /// implementation may discard it.
    async fn store_refresh_token(&self, refresh_token: &[u8]) -> SeamResult<()>;

    /// The persisted refresh token, if any.
    async fn load_refresh_token(&self) -> SeamResult<Option<Vec<u8>>>;

    /// Deletes any persisted refresh token. Idempotent.
    async fn clear_refresh_token(&self) -> SeamResult<()>;
}
