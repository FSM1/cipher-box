// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod commands;
mod fuse;
mod keychain;
mod registry;
mod state;
mod sync;
mod tray;
mod updater;

use tauri::{Manager, WindowEvent};
use state::AppState;

/// Check if WinFsp filesystem driver is installed on Windows.
///
/// Queries the Windows Registry (HKLM\SOFTWARE\WinFsp) for the install directory
/// and verifies the winfsp-x64.dll exists at the expected path.
/// Returns true if WinFsp is installed and the DLL is present.
#[cfg(target_os = "windows")]
fn check_winfsp_installed() -> bool {
    use winreg::enums::*;
    use winreg::RegKey;
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    // WinFsp is a 32-bit installer, so on 64-bit Windows the registry key
    // lives under WOW6432Node. Try the native path first, then WOW6432Node.
    let subkeys = [
        "SOFTWARE\\WinFsp",
        "SOFTWARE\\WOW6432Node\\WinFsp",
    ];
    for subkey in &subkeys {
        if let Ok(key) = hklm.open_subkey(subkey) {
            if let Ok(dir) = key.get_value::<String, _>("InstallDir") {
                let dll_path = std::path::Path::new(&dir).join("bin").join("winfsp-x64.dll");
                if dll_path.exists() {
                    return true;
                }
            }
        }
    }
    false
}

/// CLI arguments for debug builds only.
/// Allows bypassing Web3Auth login with a hex-encoded secp256k1 private key.
#[cfg(debug_assertions)]
mod cli {
    use clap::Parser;

    #[derive(Parser, Debug)]
    #[command(name = "cipherbox-desktop")]
    pub struct Args {
        /// Hex-encoded secp256k1 private key for headless auth (debug only)
        #[arg(long)]
        pub dev_key: Option<String>,
    }
}

fn main() {
    // Load .env from the desktop app root (parent of src-tauri)
    // This shares VITE_* vars between the webview and the Rust backend
    let _ = dotenvy::from_filename("../.env");

    env_logger::init();
    log::info!("CipherBox Desktop starting...");

    // Parse CLI args (debug builds only: --dev-key <hex>)
    #[cfg(debug_assertions)]
    let dev_key: Option<String> = {
        use clap::Parser;
        let args = cli::Args::parse();
        if args.dev_key.is_some() {
            log::info!("--dev-key provided: headless auth mode enabled");
        }
        args.dev_key
    };
    #[cfg(not(debug_assertions))]
    let dev_key: Option<String> = None;

    // API base URL: CIPHERBOX_API_URL > VITE_API_URL > localhost default
    let api_base_url = std::env::var("CIPHERBOX_API_URL")
        .or_else(|_| std::env::var("VITE_API_URL"))
        .unwrap_or_else(|_| "http://localhost:3000".to_string());

    let app_state = AppState::new(&api_base_url, dev_key);

    tauri::Builder::default()
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_autostart::init(
            // MacosLauncher param is macOS-specific; on Windows the plugin
            // uses Registry HKCU\...\Run automatically (param is ignored).
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .manage(app_state)
        .setup(|app| {
            // Hide dock icon -- menu bar only (pure background utility)
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            // Check WinFsp runtime is available on Windows
            #[cfg(target_os = "windows")]
            {
                if !check_winfsp_installed() {
                    log::error!("WinFsp not found. Virtual filesystem will not be available.");
                    // Show a dialog warning the user. The app can still launch
                    // (tray, settings work) but mount will fail gracefully.
                    use tauri_plugin_notification::NotificationExt;
                    let _ = app.notification()
                        .builder()
                        .title("CipherBox - WinFsp Not Found")
                        .body(
                            "WinFsp filesystem driver is not installed. CipherBox requires \
                             WinFsp to mount your encrypted vault. Please reinstall CipherBox \
                             or install WinFsp manually from https://winfsp.dev"
                        )
                        .show();
                }
            }

            // Build the system tray menu bar icon
            let handle = app.handle().clone();
            tray::build_tray(&handle)
                .map_err(|e| {
                    log::error!("Failed to build tray: {}", e);
                    let boxed: Box<dyn std::error::Error> = e.into();
                    tauri::Error::Setup(boxed.into())
                })?;

            // Initial tray status: NotConnected
            let _ = tray::update_tray_status(&handle, &tray::TrayStatus::NotConnected);

            // Check for updates on launch (5s delay, non-blocking)
            updater::check_on_launch(&handle);

            // In dev-key mode, auto-create the login webview so the JS auth
            // flow runs immediately without user interaction.
            #[cfg(debug_assertions)]
            {
                let state = handle.state::<AppState>();
                if state.dev_key.blocking_read().is_some() {
                    log::info!("Dev-key mode: auto-creating login webview");
                    let _ = tauri::WebviewWindowBuilder::new(
                        app,
                        "main",
                        tauri::WebviewUrl::App("index.html".into()),
                    )
                    .title("CipherBox")
                    .inner_size(480.0, 600.0)
                    .center()
                    .resizable(false)
                    .visible(false)
                    .on_page_load(|_webview, payload| {
                        log::info!(
                            "Webview page load: url={}, event={:?}",
                            payload.url(),
                            payload.event()
                        );
                    })
                    .build()
                    .map_err(|e| {
                        log::error!("Failed to create dev-key webview: {}", e);
                    });
                }
            }

            log::info!("CipherBox Desktop setup complete (tray icon active)");
            Ok(())
        })
        .on_window_event(|window, event| {
            // Hide the login window on close instead of destroying it.
            // The app is a menu-bar utility — only "Quit" from tray should exit.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler({
            #[cfg(debug_assertions)]
            {
                tauri::generate_handler![
                    commands::handle_auth_complete,
                    commands::handle_session_restore,
                    commands::try_silent_refresh,
                    commands::logout,
                    commands::start_sync_daemon,
                    commands::open_oauth_popup,
                    commands::get_dev_key,
                    commands::handle_test_login_complete,
                    commands::log_js_error,
                ]
            }
            #[cfg(not(debug_assertions))]
            {
                tauri::generate_handler![
                    commands::handle_auth_complete,
                    commands::handle_session_restore,
                    commands::try_silent_refresh,
                    commands::logout,
                    commands::start_sync_daemon,
                    commands::open_oauth_popup,
                ]
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running CipherBox Desktop");
}
