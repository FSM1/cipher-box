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

/// Accepts the login secret the Core Kit exported.
#[tauri::command]
pub fn session_start(request: Request<'_>, session: State<'_, Session>) -> Result<(), String> {
    let InvokeBody::Raw(bytes) = request.body() else {
        return Err("the login secret must cross as raw bytes".to_string());
    };
    // Copied out so this frame owns something it can scrub; the request's own
    // buffer belongs to the IPC layer that made it.
    let secret = Zeroizing::new(bytes.clone());
    if secret.len() != LOGIN_SECRET_LEN {
        return Err("the login secret is not a 32-byte scalar".to_string());
    }

    let mut live = session.live.lock().map_err(|_| POISONED)?;
    // One engine per running app is the desktop single-writer invariant, so a
    // second start is a bug in the caller rather than a second session.
    if *live {
        return Err("a session is already live on this device".to_string());
    }
    *live = true;
    Ok(())
}

/// Ends the session. Idempotent: the flow calls it on paths where none is live.
#[tauri::command]
pub fn session_logout(session: State<'_, Session>) -> Result<(), String> {
    *session.live.lock().map_err(|_| POISONED)? = false;
    Ok(())
}
