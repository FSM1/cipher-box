//! The tray, rendered from the engine's event stream (blueprint/desktop.md
//! "Tray").

use std::sync::Mutex;

use cipherbox_engine::Staleness;
use tauri::menu::{MenuBuilder, MenuItemBuilder, PredefinedMenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager};
use tauri_plugin_notification::NotificationExt;

use crate::engine::{EngineHost, TrayState};
use crate::mount::MountStatus;

/// ID used to look up the single tray icon instance.
pub const TRAY_ID: &str = "cipherbox-tray";

/// The lines the tray last rendered. A native menu is rebuilt to swap it, which
/// closes one the member has open, so an unchanged state costs nothing.
static PAINTED: Mutex<Option<Lines>> = Mutex::new(None);

/// Shown before a session is live. The ladder describes a vault this device is
/// reading; without one there is no rung to be on.
const SIGNED_OUT: &str = "Not signed in";

/// Shown when the session's own state could not be read. Never a rung: a tray
/// that goes on saying "Synced" is claiming something it does not know.
const UNREADABLE: &str = "CipherBox cannot read this vault's state";

/// The staleness rung as the tray says it (blueprint/desktop.md "Tray").
fn rung_label(staleness: Staleness) -> &'static str {
    match staleness {
        Staleness::Fresh => "Synced",
        Staleness::Reconciling => "Reconciling",
        Staleness::Stale => "Stale",
        Staleness::Offline => "Offline",
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

fn parked_line(parked: usize) -> String {
    let changes = if parked == 1 { "change" } else { "changes" };
    format!("{parked} {changes} cannot publish — open CipherBox on the web to resolve")
}

/// What the tray menu says, as text. Pure, so the states that must never be
/// conflated can be asserted without a tray.
#[derive(Clone, PartialEq, Eq)]
struct Lines {
    /// The one status line: a warning where there is one, the rung otherwise.
    status: String,
    /// Where the vault is on this machine, or why it is nowhere. Absent while
    /// there is no session to mount for.
    mount: Option<String>,
    /// The parked-writes section, present only while writes are parked.
    parked: Option<String>,
}

impl Lines {
    /// A warning displaces the rung rather than sitting beside it: an update
    /// being withheld and a view being old call for different reactions, and a
    /// tray that showed "Stale" for the first would tell the member to wait.
    ///
    /// Only the warning's class is rendered. The engine's own diagnostic can
    /// name a record's sequence and size, and the tray is visible to whoever
    /// can see the screen; the window is where a member reads the detail.
    fn of(state: &TrayState) -> Self {
        match state {
            TrayState::SignedOut => Self {
                status: SIGNED_OUT.to_owned(),
                mount: None,
                parked: None,
            },
            TrayState::Unreadable(_) => Self {
                status: UNREADABLE.to_owned(),
                mount: None,
                parked: None,
            },
            TrayState::Live {
                staleness,
                mount,
                parked,
                warnings,
                ..
            } => Self {
                status: match warnings.first() {
                    Some(warning) => warning_label(warning.kind).to_owned(),
                    None => rung_label(*staleness).to_owned(),
                },
                mount: Some(mount_line(mount)),
                parked: (*parked > 0).then(|| parked_line(*parked)),
            },
        }
    }
}

/// Where the vault is, or why it is nowhere. A member who thinks the mount is
/// there works in a folder nothing is watching.
fn mount_line(mount: &MountStatus) -> String {
    match mount {
        MountStatus::Opening => "Mounting your vault…".to_owned(),
        MountStatus::Mounted { path } => format!("Mounted at {path}"),
        MountStatus::Refused { reason } => reason.clone(),
    }
}

/// Build and register the tray icon, with the menu a signed-out shell shows.
pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let lines = Lines::of(&TrayState::SignedOut);
    TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu(app, &lines)?)
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
    remember(lines);
    Ok(())
}

/// Render one engine state into the tray, and announce parked writes the member
/// has not been told about yet.
pub fn paint(app: &AppHandle, state: &TrayState) {
    // The tray says the class; why it could not be read is a diagnostic, and
    // the tray is visible to whoever can see the screen.
    if let TrayState::Unreadable(reason) = state {
        eprintln!("the vault's state could not be read: {reason}");
    }
    let lines = Lines::of(state);
    if let (TrayState::Live { newly_parked, .. }, Some(parked)) = (state, &lines.parked)
        && *newly_parked
    {
        announce(app, parked);
    }
    if remember(lines.clone()) {
        set_menu(app, &lines);
    }
}

/// Whether `lines` differ from what the tray already shows, taking them as the
/// new baseline either way.
fn remember(lines: Lines) -> bool {
    let Ok(mut painted) = PAINTED.lock() else {
        return true;
    };
    let previous = painted.replace(lines);
    previous.as_ref() != painted.as_ref()
}

fn announce(app: &AppHandle, body: &str) {
    let _ = app
        .notification()
        .builder()
        .title("CipherBox")
        .body(body)
        .show();
}

/// The menu is rebuilt rather than edited: the mount and parked-writes sections
/// come and go, and a tray item cannot be hidden.
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
    let mut builder = MenuBuilder::new(app).item(
        &MenuItemBuilder::with_id("status", &lines.status)
            .enabled(false)
            .build(app)?,
    );
    for (id, line) in [("mount", &lines.mount), ("parked", &lines.parked)] {
        if let Some(line) = line {
            builder = builder.item(
                &MenuItemBuilder::with_id(id, line)
                    .enabled(false)
                    .build(app)?,
            );
        }
    }
    builder
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&MenuItemBuilder::with_id("sync", "Sync Now").build(app)?)
        .item(&MenuItemBuilder::with_id("open", "Open CipherBox").build(app)?)
        .item(&PredefinedMenuItem::separator(app)?)
        .item(&MenuItemBuilder::with_id("quit", "Quit CipherBox").build(app)?)
        .build()
}

/// Shown when a refresh the member asked for did not land. The engine's own
/// words for why stay off the tray; the rung is what says where the vault is.
const SYNC_REFUSED: &str = "CipherBox could not sync this vault";

/// "Sync Now" is the manual-refresh facade command; what it changes arrives on
/// the event stream and repaints this menu.
fn sync_now(app: &AppHandle) {
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // A refusal on an action the member took is one they must see, and a
        // packaged app has no console they read.
        if let Err(error) = app.state::<EngineHost>().refresh().await {
            eprintln!("sync now: {error}");
            announce(&app, SYNC_REFUSED);
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

    fn live(staleness: Staleness, warnings: Vec<VaultWarning>, parked: usize) -> TrayState {
        TrayState::Live {
            staleness,
            mount: MountStatus::Mounted {
                path: "/home/member/CipherBox".to_owned(),
            },
            parked,
            newly_parked: false,
            warnings,
        }
    }

    /// A withheld update is a warning, not a rung: a tray that said "Stale"
    /// would tell the member to wait for something that is not coming.
    #[test]
    fn a_warning_is_never_rendered_as_a_staleness_rung() {
        let withheld = live(
            Staleness::Stale,
            vec![VaultWarning {
                kind: "withheldUpdateEscalation",
                detail: Some("a record of 12345 bytes".to_owned()),
            }],
            0,
        );
        let status = Lines::of(&withheld).status;
        assert_eq!(status, warning_label("withheldUpdateEscalation"));
        assert!(
            !status.contains("12345"),
            "the tray says the class, never the engine's diagnostic",
        );
        for rung in [
            Staleness::Fresh,
            Staleness::Reconciling,
            Staleness::Stale,
            Staleness::Offline,
        ] {
            assert_ne!(status, rung_label(rung));
        }
    }

    #[test]
    fn each_rung_is_the_line_the_tray_shows_for_it() {
        for (rung, label) in [
            (Staleness::Fresh, "Synced"),
            (Staleness::Reconciling, "Reconciling"),
            (Staleness::Stale, "Stale"),
            (Staleness::Offline, "Offline"),
        ] {
            assert_eq!(Lines::of(&live(rung, Vec::new(), 0)).status, label);
        }
    }

    /// Parked writes are a section of their own, and only there when there are
    /// any — never folded into the line that says how fresh the view is.
    #[test]
    fn parked_writes_get_their_own_section_only_when_there_are_any() {
        assert_eq!(
            Lines::of(&live(Staleness::Fresh, Vec::new(), 0)).parked,
            None
        );

        let parked = Lines::of(&live(Staleness::Fresh, Vec::new(), 2));
        assert_eq!(parked.status, "Synced");
        assert!(
            parked.parked.expect("a section").contains("2 changes"),
            "the member is told how much is parked"
        );
    }

    /// A mount refusal never fails the session, so the tray is where a member
    /// with the window closed finds out the vault is not on disk.
    #[test]
    fn a_mount_refusal_reaches_the_tray_rather_than_only_the_window() {
        let refused = TrayState::Live {
            staleness: Staleness::Fresh,
            mount: MountStatus::Refused {
                reason: "/home/member/CipherBox is not empty".to_owned(),
            },
            parked: 0,
            newly_parked: false,
            warnings: Vec::new(),
        };
        let lines = Lines::of(&refused);
        assert_eq!(
            lines.status, "Synced",
            "a refused mount is not a stale view"
        );
        assert_eq!(
            lines.mount.as_deref(),
            Some("/home/member/CipherBox is not empty")
        );
    }

    /// A state that cannot be read must not go on claiming the last one it
    /// could — the tray is the surface a trust warning lands on.
    #[test]
    fn a_state_that_cannot_be_read_is_never_rendered_as_a_healthy_one() {
        let lines = Lines::of(&TrayState::Unreadable("the queue did not open".to_owned()));
        assert_eq!(lines.status, UNREADABLE);
        assert_eq!(lines.parked, None);
    }
}
