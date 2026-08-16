//! The `LoginFacade` the shared login sequence starts, over Tauri IPC
//! (blueprint/desktop.md, "Tauri shell").
//!
//! **The engine is not linked into this shell yet.** `crates/desktop-seams`
//! holds the seam set the native host will inject, but nothing here constructs
//! an engine, so these commands are where the login stops rather than where it
//! hands over: `session_start` takes the login secret, checks it is the scalar
//! the engine will require, and zeroizes it. There is no vault state behind
//! them, and the shell's window says so.

use std::sync::Mutex;

use tauri::State;
use tauri::ipc::{InvokeBody, Request};
use zeroize::Zeroizing;

/// The secp256k1 scalar length `crates/engine/src/session.rs` requires.
const LOGIN_SECRET_LEN: usize = 32;

const POISONED: &str = "the session state is unreadable; restart CipherBox";

/// Whether a login has completed on this device since the shell started.
#[derive(Default)]
pub struct Session {
    live: Mutex<bool>,
}

impl Session {
    /// Takes the secret by value so this is where it is scrubbed: the path that
    /// carries it ends here until the engine is linked in.
    fn start(&self, _secret: Zeroizing<Vec<u8>>) -> Result<(), String> {
        let mut live = self.live.lock().map_err(|_| POISONED)?;
        // One engine per running app is the desktop single-writer invariant, so
        // a second start is a bug in the caller rather than a second session.
        if *live {
            return Err("a session is already live on this device".to_string());
        }
        *live = true;
        Ok(())
    }

    /// Idempotent: the flow calls it on paths where no session is live.
    fn end(&self) -> Result<(), String> {
        *self.live.lock().map_err(|_| POISONED)? = false;
        Ok(())
    }
}

/// The login secret an invoke body carries, or why it is not one.
fn login_secret(body: &InvokeBody) -> Result<Zeroizing<Vec<u8>>, String> {
    let InvokeBody::Raw(bytes) = body else {
        return Err("the login secret must cross as raw bytes".to_string());
    };
    // Copied out so this frame owns something it can scrub; the request's own
    // buffer belongs to the IPC layer that made it.
    let secret = Zeroizing::new(bytes.clone());
    if secret.len() != LOGIN_SECRET_LEN {
        return Err("the login secret is not a 32-byte scalar".to_string());
    }
    Ok(secret)
}

/// Accepts the login secret the Core Kit exported.
#[tauri::command]
pub fn session_start(request: Request<'_>, session: State<'_, Session>) -> Result<(), String> {
    session.start(login_secret(request.body())?)
}

/// Ends the session.
#[tauri::command]
pub fn session_logout(session: State<'_, Session>) -> Result<(), String> {
    session.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar() -> Zeroizing<Vec<u8>> {
        Zeroizing::new(vec![7u8; LOGIN_SECRET_LEN])
    }

    #[test]
    fn refuses_a_secret_that_did_not_cross_as_raw_bytes() {
        let json = InvokeBody::Json(serde_json::json!([7, 7, 7]));
        assert!(login_secret(&json).is_err());
    }

    #[test]
    fn refuses_a_secret_that_is_not_a_32_byte_scalar() {
        assert!(login_secret(&InvokeBody::Raw(vec![7u8; 31])).is_err());
        assert!(login_secret(&InvokeBody::Raw(vec![7u8; 33])).is_err());
        assert!(login_secret(&InvokeBody::Raw(Vec::new())).is_err());
        assert!(login_secret(&InvokeBody::Raw(vec![7u8; LOGIN_SECRET_LEN])).is_ok());
    }

    #[test]
    fn refuses_a_second_start_while_one_is_live() {
        let session = Session::default();
        assert!(session.start(scalar()).is_ok());
        assert!(session.start(scalar()).is_err());

        // …and the device takes a new one once the first has ended.
        assert!(session.end().is_ok());
        assert!(session.start(scalar()).is_ok());
    }

    #[test]
    fn ends_a_session_that_was_never_live() {
        let session = Session::default();
        assert!(session.end().is_ok());
        assert!(session.end().is_ok());
    }
}
