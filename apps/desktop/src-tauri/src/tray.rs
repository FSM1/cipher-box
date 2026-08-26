//! The tray, rendered from the engine's event stream (blueprint/desktop.md
//! "Tray").
//!
//! The staleness ladder is the status line; a trust violation or a withheld
//! update is a warning state of its own and never a rung on that ladder
//! (FSM1/cipher-box-next#33 D4). Parked writes get a section that is always there
//! when there are any, and a notification only when there are more than the
//! member has already been told about.

use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::engine::{EngineHost, TrayState};

/// ID used to look up the single tray icon instance.
pub const TRAY_ID: &str = "cipherbox-tray";

/// Shown before a session is live. The ladder describes a vault this device is
/// reading; without one there is no rung to be on.
const SIGNED_OUT: &str = "Not signed in";

/// The staleness rung as the tray says it (blueprint/desktop.md "Tray").
fn rung_label(staleness: &str) -> &'static str {
    match staleness {
        "fresh" => "Synced",
        "reconciling" => "Reconciling",
        "stale" => "Stale",
        _ => "Offline",
    }
}

/// One engine warning as the tray says it. The fallback keeps a class the
/// engine gains before this table does from rendering as nothing at all.
fn warning_label(kind: &str) -> &'static str {
    match kind {
        "attributableAbuse" => "CipherBox refused an update that failed a trust check",
        "withheldUpdateEscalation" => "A shared folder is being kept from its latest update",
        "renewalFailed" => "CipherBox could not renew a record, so it may expire",
        _ => "CipherBox raised a condition it could not name",
    }
}

/// What the tray menu says, as text. Pure, so the states that must never be
/// conflated can be asserted without a tray.
struct Lines {
    /// The one status line: a warning where there is one, the rung otherwise.
    status: String,
    /// The parked-writes section, present only while writes are parked.
    parked: Option<String>,
}

impl Lines {
    /// A warning displaces the rung rather than sitting beside it: an update
    /// being withheld and a view being old call for different reactions, and a
    /// tray that showed "Stale" for the first would tell the member to wait.
    fn of(state: &TrayState) -> Self {
        let status = match state.warnings.first() {
            Some(warning) => match &warning.detail {
                Some(detail) => format!("{} — {detail}", warning_label(warning.kind)),
                None => warning_label(warning.kind).to_owned(),
            },
            None => rung_label(state.staleness).to_owned(),
        };
        Self {
            status,
            parked: (state.parked > 0).then(|| parked_line(state.parked)),
        }
    }
}

fn parked_line(parked: usize) -> String {
    let changes = if parked == 1 { "change" } else { "changes" };
    format!("{parked} {changes} cannot publish — open CipherBox to resolve")
}

/// Build and register the tray icon, with the menu a signed-out shell shows.
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu(
            app,
            &Lines {
                status: SIGNED_OUT.to_owned(),
                parked: None,
            },
        )?)
        .tooltip("CipherBox")
        .icon(icon()?)
        .icon_as_template(cfg!(target_os = "macos"))
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => crate::show_main_window(app),
            "sync" => sync_now(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

/// Render one engine state into the tray, and announce parked writes the member
/// has not been told about yet.
pub fn paint(app: &AppHandle, state: &TrayState) {
    let lines = Lines::of(state);
    if state.newly_parked {
        let _ = app
            .notification()
            .builder()
            .title("CipherBox")
            .body(parked_line(state.parked))
            .show();
    }
    set_menu(app, &lines);
}

/// Return the tray to what it says with no session behind it.
pub fn signed_out(app: &AppHandle) {
    set_menu(
        app,
        &Lines {
            status: SIGNED_OUT.to_owned(),
            parked: None,
        },
    );
}

/// The menu is rebuilt rather than edited: the parked-writes section is present
/// only while there are parked writes, and a tray item cannot be hidden.
fn set_menu(app: &AppHandle, lines: &Lines) {
    let Some(tray) = app.tray_by_id(TRAY_ID) else {
        return;
    };
    match menu(app, lines) {
        Ok(menu) => {
            if let Err(error) = tray.set_menu(Some(menu)) {
                eprintln!("failed to update the tray menu: {error}");
            }
        }
        Err(error) => eprintln!("failed to build the tray menu: {error}"),
    }
}

fn menu(app: &AppHandle, lines: &Lines) -> tauri::Result<tauri::menu::Menu<tauri::Wry>> {
    let status = MenuItemBuilder::with_id("status", &lines.status)
        .enabled(false)
        .build(app)?;
    let sync = MenuItemBuilder::with_id("sync", "Sync Now").build(app)?;
    let open = MenuItemBuilder::with_id("open", "Open CipherBox").build(app)?;
    let quit = MenuItemBuilder::with_id("quit", "Quit CipherBox").build(app)?;

    let mut builder = MenuBuilder::new(app).item(&status);
    if let Some(parked) = &lines.parked {
        builder = builder.item(
            &MenuItemBuilder::with_id("parked", parked)
                .enabled(false)
                .build(app)?,
        );
    }
    builder
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&sync)
        .item(&open)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&quit)
        .build()
}

/// "Sync Now" is the manual-refresh facade command; what it changes arrives on
/// the event stream and repaints this menu.
fn sync_now(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        if let Err(error) = app.state::<EngineHost>().refresh().await {
            eprintln!("sync now: {error}");
        }
    });
}

/// Load the platform-appropriate tray icon (template icon on macOS).
fn icon() -> tauri::Result<tauri::image::Image<'static>> {
    #[cfg(target_os = "macos")]
    let bytes: &[u8] = include_bytes!("../icons/tray-icon@2x.png");
    #[cfg(target_os = "windows")]
    let bytes: &[u8] = include_bytes!("../icons/icon.ico");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let bytes: &[u8] = include_bytes!("../icons/tray-icon-linux@2x.png");

    tauri::image::Image::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::VaultWarning;

    fn state(staleness: &'static str, warnings: Vec<VaultWarning>, parked: usize) -> TrayState {
        TrayState {
            staleness,
            parked,
            newly_parked: false,
            warnings,
        }
    }

    /// A withheld update is a warning, not a rung: a tray that said "Stale"
    /// would tell the member to wait for something that is not coming.
    #[test]
    fn a_warning_is_never_rendered_as_a_staleness_rung() {
        let withheld = state(
            "stale",
            vec![VaultWarning {
                kind: "withheldUpdateEscalation",
                detail: None,
            }],
            0,
        );
        let status = Lines::of(&withheld).status;
        assert_eq!(status, warning_label("withheldUpdateEscalation"));
        for rung in ["fresh", "reconciling", "stale", "offline"] {
            assert_ne!(status, rung_label(rung));
        }
    }

    #[test]
    fn each_rung_is_the_line_the_tray_shows_for_it() {
        for (rung, label) in [
            ("fresh", "Synced"),
            ("reconciling", "Reconciling"),
            ("stale", "Stale"),
            ("offline", "Offline"),
        ] {
            assert_eq!(Lines::of(&state(rung, Vec::new(), 0)).status, label);
        }
    }

    /// Parked writes are a section of their own, and only there when there are
    /// any — never folded into the line that says how fresh the view is.
    #[test]
    fn parked_writes_get_their_own_section_only_when_there_are_any() {
        assert_eq!(Lines::of(&state("fresh", Vec::new(), 0)).parked, None);

        let parked = Lines::of(&state("fresh", Vec::new(), 2));
        assert_eq!(parked.status, "Synced");
        assert!(
            parked.parked.expect("a section").contains("2 changes"),
            "the member is told how much is parked"
        );
    }
}
