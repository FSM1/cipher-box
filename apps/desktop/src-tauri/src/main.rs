// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod commands;
mod crypto;
mod fuse;
mod registry;
mod state;
mod sync;
mod tray;

use tauri::WindowEvent;
use state::AppState;

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
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_notification::init())
        .manage(app_state)
        .setup(|app| {
            // Hide dock icon -- menu bar only (pure background utility)
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

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
        .invoke_handler(tauri::generate_handler![
            commands::handle_auth_complete,
            commands::try_silent_refresh,
            commands::logout,
            commands::start_sync_daemon,
            commands::get_dev_key,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherBox Desktop");
}
