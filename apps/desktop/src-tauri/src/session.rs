//! The `LoginFacade` the shared login sequence starts, over Tauri IPC
//! (blueprint/desktop.md, "Tauri shell"), and the one read the signed-in window
//! renders.
//!
//! These commands are the handover: `session_start` takes the login secret and
//! hands it to the engine ([`crate::engine`]), which is where it stops being
//! this shell's to hold. The webview never sees a key, a token, or a name — the
//! only thing that comes back out is [`VaultStatus`].

use cipherbox_desktop_seams::{KeyringCredentialStore, SealedCoreKitStore, core_kit_store_dir};
use tauri::ipc::{InvokeBody, Request};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::engine::{
    EngineConfig, EngineHost, LOGIN_SECRET_LEN, NOT_A_SCALAR, OsEntropy, SessionEnv, Shell,
    VaultStatus,
};
use crate::tray;

/// Fired when the engine emits, so the window re-reads what it renders.
pub const VAULT_CHANGED: &str = "vault-changed";

/// The device's Core Kit store, as the shell holds it.
type CoreKitStore = SealedCoreKitStore<KeyringCredentialStore>;

/// Opens the app's one keyring handle and the Core Kit store it seals, and
/// hands both to Tauri to hold.
///
/// One keyring handle for the whole app: its worker queue is what orders a
/// credential write against the logout delete issued after it, and two handles
/// would be two queues.
pub fn open_key_custody(app: &AppHandle) -> Result<(), String> {
    let credentials = KeyringCredentialStore::new(app.config().identifier.clone())
        .map_err(|error| error.to_string())?;
    let data_local_dir = app
        .path()
        .local_data_dir()
        .map_err(|error| format!("this device has no local data directory: {error}"))?;
    let core_kit = CoreKitStore::open(
        core_kit_store_dir(&data_local_dir),
        credentials.clone(),
        Box::new(OsEntropy),
    )
    .map_err(|error| error.to_string())?;
    app.manage(credentials);
    app.manage(core_kit);
    Ok(())
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
        credentials: app.state::<KeyringCredentialStore>().inner().clone(),
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
pub fn session_logout(engine: State<'_, EngineHost>) {
    engine.log_out();
}

/// Forgets this device: everything a logout does, then the durable stores a
/// logout keeps, then the Core Kit store. Nothing of this account is left on
/// this machine, in the keyring included.
///
/// The engine leg runs on a blocking thread — it waits on the engine thread and
/// then on the filesystem — and the Core Kit purge runs whichever way it went:
/// a sweep that stopped at the first refusal would report a forget that did not
/// land.
#[tauri::command]
pub async fn session_forget_device(
    app: AppHandle,
    core_kit: State<'_, CoreKitStore>,
) -> Result<(), String> {
    let forgotten =
        tauri::async_runtime::spawn_blocking(move || app.state::<EngineHost>().forget_device())
            .await
            .map_err(|error| format!("forgetting this device did not finish: {error}"))?;
    let purged = core_kit.purge().await.map_err(|error| error.to_string());
    forgotten.and(purged)
}

/// One Core Kit store slot, or `None` when this device holds nothing openable
/// for it. The login SDK reads this before a session exists, so the engine
/// cannot serve it (blueprint/desktop.md, "Tauri shell").
#[tauri::command]
pub async fn core_kit_get_item(
    core_kit: State<'_, CoreKitStore>,
    key: String,
) -> Result<Option<String>, String> {
    core_kit
        .get_item(&key)
        .await
        .map_err(|error| error.to_string())
}

/// Seals one Core Kit store slot. What lands on disk is ciphertext; the key
/// that opens it stays in the OS keyring.
#[tauri::command]
pub async fn core_kit_set_item(
    core_kit: State<'_, CoreKitStore>,
    key: String,
    value: String,
) -> Result<(), String> {
    core_kit
        .set_item(&key, &value)
        .await
        .map_err(|error| error.to_string())
}

/// Drops every Core Kit store slot and the key that opens them — what a sign-out
/// leaves behind otherwise is a device factor at rest.
#[tauri::command]
pub async fn core_kit_purge(core_kit: State<'_, CoreKitStore>) -> Result<(), String> {
    core_kit.purge().await.map_err(|error| error.to_string())
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
