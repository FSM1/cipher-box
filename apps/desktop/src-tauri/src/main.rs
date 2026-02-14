// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod commands;
mod crypto;
mod fuse;
mod state;
mod sync;
mod tray;

use tauri::WindowEvent;
use state::AppState;

fn main() {
    env_logger::init();
    log::info!("CipherBox Desktop starting...");

    // API base URL: use env var or default to localhost for development
    let api_base_url =
        std::env::var("CIPHERBOX_API_URL").unwrap_or_else(|_| "http://localhost:3000".to_string());

    let app_state = AppState::new(&api_base_url);

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
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherBox Desktop");
}
