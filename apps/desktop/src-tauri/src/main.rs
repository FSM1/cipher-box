//! CipherBox desktop shell — Tauri v2 menu-bar app.
//!
//! Hosts the login front door (`../src`, driving `@cipherbox/login`), the two
//! native steps that front door cannot take itself — Google collection over a
//! loopback callback ([`oauth`]) and the facade the sequence starts
//! ([`session`]) — the engine that facade hands the login secret to
//! ([`engine`]), and the filesystem that engine is projected through
//! ([`mount`]).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod engine;
mod mount;
mod oauth;
mod session;
mod tray;

use tauri::{AppHandle, Manager, RunEvent, WindowEvent};

/// Label of the one (hidden-by-default) main window.
const MAIN_WINDOW: &str = "main";

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_notification::init())
        .manage(engine::EngineHost::default())
        .invoke_handler(tauri::generate_handler![
            oauth::collect_google_id_token,
            session::session_start,
            session::session_logout,
            session::session_forget_device,
            session::vault_status,
            session::core_kit_get_item,
            session::core_kit_set_item,
            session::core_kit_purge
        ])
        .setup(|app| {
            // Menu-bar app: no Dock icon on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            session::open_key_custody(app.handle())?;
            tray::build(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // The main window hides instead of closing: the shell lives in
            // the tray until the user quits from there.
            if window.label() == MAIN_WINDOW {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build the CipherBox desktop shell")
        .run(|app, event| match event {
            // Keep running from the tray when every window is hidden; only an
            // explicit exit (tray "Quit") carries an exit code.
            RunEvent::ExitRequested {
                code: None, api, ..
            } => api.prevent_exit(),
            // Quit ends the session before the process goes: the mount is
            // quiesced and unmounted and the engine's loops end, rather than
            // both being left to the exit.
            RunEvent::Exit => app.state::<engine::EngineHost>().stop(),
            _ => {}
        });
}

/// Show and focus the main window from the tray.
pub fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        if let Err(error) = window.show() {
            eprintln!("failed to show the main window: {error}");
        }
        if let Err(error) = window.set_focus() {
            eprintln!("failed to focus the main window: {error}");
        }
    }
}
