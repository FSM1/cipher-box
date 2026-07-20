//! CipherBox desktop shell — Tauri v2 menu-bar/tray skeleton.
//!
//! Scaffold only: no engine wiring, no login, no mount, no vault semantics.
//! The tray and the hidden main window are the lifecycle chrome the engine
//! host attaches to in a later slice (blueprint/desktop.md, "Tauri shell").

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};

/// ID used to look up the single tray icon instance.
const TRAY_ID: &str = "cipherbox-tray";

/// Label of the one (hidden-by-default) main window.
const MAIN_WINDOW: &str = "main";

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            // Menu-bar app: no Dock icon on macOS.
            #[cfg(target_os = "macos")]
            app.set_activation_policy(tauri::ActivationPolicy::Accessory);

            build_tray(app.handle())?;
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
        .run(|_app, event| {
            // Keep running from the tray when every window is hidden; only an
            // explicit exit (tray "Quit") carries an exit code.
            if let RunEvent::ExitRequested {
                code: None, api, ..
            } = event
            {
                api.prevent_exit();
            }
        });
}

/// Build and register the tray icon with the skeleton menu:
/// a disabled status line, "Open CipherBox", and "Quit CipherBox".
fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItemBuilder::with_id("status", "Not signed in")
        .enabled(false)
        .build(app)?;
    let open = MenuItemBuilder::with_id("open", "Open CipherBox").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit CipherBox").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&status)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&open)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&quit)
        .build()?;

    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("CipherBox")
        .icon(tray_icon()?)
        .icon_as_template(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main_window(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;

    Ok(())
}

/// Load the platform-appropriate tray icon (template icon on macOS).
fn tray_icon() -> tauri::Result<tauri::image::Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = include_bytes!("../icons/tray-icon@2x.png");
    #[cfg(target_os = "windows")]
    let bytes: &[u8] = include_bytes!("../icons/icon.ico");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let bytes: &[u8] = include_bytes!("../icons/tray-icon-linux@2x.png");

    tauri::image::Image::from_bytes(bytes)
}

/// Show and focus the main window from the tray.
fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.show();
        let _ = window.set_focus();
    }
}
