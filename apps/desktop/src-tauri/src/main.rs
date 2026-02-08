// Prevents additional console window on Windows in release
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod api;
mod commands;
mod crypto;
mod state;

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

            log::info!("CipherBox Desktop setup complete");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::handle_auth_complete,
            commands::try_silent_refresh,
            commands::logout,
        ])
        .run(tauri::generate_context!())
        .expect("error while running CipherBox Desktop");
}
