//! Tauri IPC commands for the desktop auth flow.
//!
//! These commands are invoked from the webview (TypeScript) via Tauri's
//! `invoke()` API. They handle authentication, vault key decryption,
//! Keychain storage, and logout.

mod auth;
mod vault;
mod sync;
mod oauth;
#[cfg(debug_assertions)]
mod debug;
mod util;

pub use auth::*;
pub use sync::*;
pub use oauth::*;
#[cfg(debug_assertions)]
pub use debug::*;
