//! The `LoginFacade` the shared login sequence starts, over Tauri IPC
//! (blueprint/desktop.md, "Tauri shell"), and the one read the signed-in window
//! renders.
//!
//! These commands are the handover: `session_start` takes the login secret and
//! hands it to the engine ([`crate::engine`]), which is where it stops being
//! this shell's to hold. The webview never sees a key, a token, or a name — the
//! only thing that comes back out is [`VaultStatus`].

use tauri::ipc::{InvokeBody, Request};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::engine::{
    EngineConfig, EngineHost, LOGIN_SECRET_LEN, NOT_A_SCALAR, SessionEnv, Shell, VaultStatus,
};
use crate::tray;

/// Fired when the engine emits, so the window re-reads what it renders.
pub const VAULT_CHANGED: &str = "vault-changed";

/// The login secret an invoke body carries, or why it is not one.
fn login_secret(body: &InvokeBody) -> Result<Zeroizing<Vec<u8>>, String> {
    let InvokeBody::Raw(bytes) = body else {
        return Err("the login secret must cross as raw bytes".to_string());
    };
    // Copied out so this frame owns something it can scrub; the request's own
    // buffer belongs to the IPC layer that made it.
    let secret = Zeroizing::new(bytes.clone());
    if secret.len() != LOGIN_SECRET_LEN {
        return Err(NOT_A_SCALAR.to_string());
    }
    Ok(secret)
}

/// Where this session's stores live and how the window and tray hear about
/// changes.
fn session_env(app: &AppHandle) -> Result<SessionEnv, String> {
    let painting = app.clone();
    let repainting = app.clone();
    Ok(SessionEnv {
        config: EngineConfig::compiled()?,
        data_local_dir: app
            .path()
            .local_data_dir()
            .map_err(|error| format!("this device has no local data directory: {error}"))?,
        home_dir: app.path().home_dir().ok(),
        keyring_service: app.config().identifier.clone(),
        shell: Shell {
            changed: Box::new(move || {
                let _ = repainting.emit(VAULT_CHANGED, ());
            }),
            tray: Box::new(move |state| tray::paint(&painting, &state)),
        },
    })
}

/// Accepts the login secret the Core Kit exported and starts the engine on it.
#[tauri::command]
pub async fn session_start(
    app: AppHandle,
    request: Request<'_>,
    engine: State<'_, EngineHost>,
) -> Result<(), String> {
    let secret = login_secret(request.body())?;
    engine.start(secret, session_env(&app)?).await
}

/// Ends the session: the engine stops and drops, and this device's stored
/// refresh token goes with it.
///
/// `async` so a sync body runs on the thread pool rather than inline on the
/// IPC thread: this waits on the engine thread, and the keyring delete inside
/// it is a blocking OS call.
#[tauri::command(async)]
pub fn session_logout(app: AppHandle, engine: State<'_, EngineHost>) {
    engine.log_out();
    tray::signed_out(&app);
}

/// Forgets this device: everything a logout does, and then the durable stores a
/// logout keeps. Nothing of this account is left on this machine.
///
/// `async` for the same reason [`session_logout`] is — this waits on the engine
/// thread and then on the filesystem.
#[tauri::command(async)]
pub fn session_forget_device(app: AppHandle, engine: State<'_, EngineHost>) -> Result<(), String> {
    let forgotten = engine.forget_device();
    tray::signed_out(&app);
    forgotten
}

/// The live vault's status, as the signed-in window renders it.
#[tauri::command]
pub async fn vault_status(engine: State<'_, EngineHost>) -> Result<VaultStatus, String> {
    engine.status().await
}

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The window keys its listener off this name, so it is part of the IPC
    /// surface rather than a private label.
    #[test]
    fn the_repaint_event_keeps_its_name() {
        assert_eq!(VAULT_CHANGED, "vault-changed");
    }
}
