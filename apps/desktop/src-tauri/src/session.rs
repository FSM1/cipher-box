//! The `LoginFacade` the shared login sequence starts, over Tauri IPC
//! (blueprint/desktop.md, "Tauri shell"), and the one read the signed-in window
//! renders.
//!
//! These commands are the handover: `session_start` takes the login secret and
//! hands it to the engine ([`crate::engine`]), which is where it stops being
//! this shell's to hold. Nothing the engine holds comes back out — the only
//! value it returns to the webview is [`VaultStatus`].
//!
//! The `core_kit_*` commands are the one exception, and are not the engine's:
//! they hand the login SDK back its own store, which that SDK reads before a
//! session exists and already holds in webview memory. What this side adds is
//! custody at rest — the slots are sealed under a keyring-held key
//! ([`SealedCoreKitStore`]), which the webview never sees.

use cipherbox_desktop_seams::{KeyringCredentialStore, SealedCoreKitStore, core_kit_store_dir};
use tauri::ipc::{InvokeBody, Request};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

use crate::engine::{
    EngineConfig, EngineHost, HostCredentialStore, LOGIN_SECRET_LEN, NOT_A_SCALAR, OsEntropy,
    SessionEnv, Shell, VaultStatus,
};
use crate::tray;

/// Fired when the engine emits, so the window re-reads what it renders.
pub const VAULT_CHANGED: &str = "vault-changed";

/// The device's Core Kit store, as the shell holds it.
type CoreKitStore = SealedCoreKitStore<KeyringCredentialStore>;

/// Opens the app's one keyring handle and the Core Kit store it seals, and
/// hands both to Tauri to hold.
pub fn open_key_custody(app: &AppHandle) -> Result<(), String> {
    let credentials = KeyringCredentialStore::new(app.config().identifier.clone())
        .map_err(|error| error.to_string())?;
    let core_kit = CoreKitStore::open(
        core_kit_store_dir(&local_data_dir(app)?),
        credentials.clone(),
        Box::new(OsEntropy),
    )
    .map_err(|error| error.to_string())?;
    app.manage(credentials);
    app.manage(core_kit);
    Ok(())
}

fn local_data_dir(app: &AppHandle) -> Result<std::path::PathBuf, String> {
    app.path()
        .local_data_dir()
        .map_err(|error| format!("this device has no local data directory: {error}"))
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

/// This session's [`HostCredentialStore`].
#[cfg(not(feature = "e2e-hook"))]
fn session_credentials(app: &AppHandle) -> HostCredentialStore {
    app.state::<KeyringCredentialStore>().inner().clone()
}

#[cfg(feature = "e2e-hook")]
fn session_credentials(_app: &AppHandle) -> HostCredentialStore {
    HostCredentialStore::default()
}

/// Where this session's stores live and how the window and tray hear about
/// changes.
pub(crate) fn session_env(app: &AppHandle) -> Result<SessionEnv, String> {
    let painting = app.clone();
    let repainting = app.clone();
    Ok(SessionEnv {
        config: EngineConfig::compiled()?,
        data_local_dir: local_data_dir(app)?,
        home_dir: app.path().home_dir().ok(),
        credentials: session_credentials(app),
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

/// Ends the session: the engine revokes this device's credential and stops.
///
/// The join runs off the async runtime: it waits on the engine thread, whose
/// last request reaches the network and the keyring.
#[tauri::command]
pub async fn session_logout(app: AppHandle) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || app.state::<EngineHost>().log_out())
        .await
        .unwrap_or_else(|error| Err(format!("signing out did not finish: {error}")))
}

/// Forgets this device: everything a logout does, then the durable stores a
/// logout keeps, then the Core Kit store. Nothing of this account is left on
/// this machine, in the keyring included — and the Core Kit store is the
/// device's rather than the account's, so what every account on it held goes
/// too.
///
/// The engine leg waits on the engine thread and then on the filesystem, so it
/// runs off the async runtime. The two legs run together: they share no
/// directory and no keyring account, and neither refusal spares the other.
#[tauri::command]
pub async fn session_forget_device(
    app: AppHandle,
    core_kit: State<'_, CoreKitStore>,
) -> Result<(), String> {
    let (forgotten, purged) = tokio::join!(
        tauri::async_runtime::spawn_blocking(move || app.state::<EngineHost>().forget_device()),
        core_kit.purge(),
    );
    let forgotten = forgotten
        .unwrap_or_else(|error| Err(format!("forgetting this device did not finish: {error}")));
    forgotten.and(purged.map_err(|error| error.to_string()))
}

/// One Core Kit store slot, or `None` when this device holds nothing openable
/// for it.
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
