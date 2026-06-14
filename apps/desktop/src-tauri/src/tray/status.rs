//! Status state machine for the system tray icon.
//!
//! Represents all possible states of the desktop app as displayed
//! in the menu bar tray icon's status line.

/// All possible states the desktop app can be in.
///
/// The tray menu status line displays the human-readable label
/// returned by `TrayStatus::label()`.
#[derive(Debug, Clone, PartialEq)]
pub enum TrayStatus {
    /// No auth, no mount -- initial state and post-logout state.
    NotConnected,
    /// Auth complete, FUSE filesystem is mounting.
    Mounting,
    /// Background sync is actively polling/refreshing metadata.
    Syncing,
    /// Up to date -- last sync completed successfully.
    Synced,
    /// Network unavailable -- waiting for connectivity to resume.
    Offline,
    /// Something went wrong (with human-readable description).
    Error(String),
    /// One or more uploads permanently failed and are parked on disk (D-10).
    ///
    /// Displayed when `SyncStatus::WriteParked { failed > 0 }` is received.
    WriteParked,
}

impl TrayStatus {
    /// Human-readable status text for the tray menu item.
    pub fn label(&self) -> &str {
        match self {
            TrayStatus::NotConnected => "Not Connected",
            TrayStatus::Mounting => "Mounting...",
            TrayStatus::Syncing => "Syncing...",
            TrayStatus::Synced => "Synced",
            TrayStatus::Offline => "Offline",
            TrayStatus::Error(_) => "Error",
            TrayStatus::WriteParked => "Upload Failed",
        }
    }

    /// Returns `true` when the app is authenticated and has (or had) a mounted filesystem.
    ///
    /// True for Syncing, Synced, Offline, and WriteParked — states where the user is
    /// authenticated and can still take recovery actions. In particular WriteParked keeps
    /// Logout enabled (gated on this) so a user with parked uploads is not locked out of
    /// the tray. (Open/Sync are gated separately by `is_mounted`/`is_syncable`.)
    /// False for NotConnected, Mounting, Error.
    pub fn is_connected(&self) -> bool {
        matches!(
            self,
            TrayStatus::Syncing
                | TrayStatus::Synced
                | TrayStatus::Offline
                | TrayStatus::WriteParked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels() {
        assert_eq!(TrayStatus::NotConnected.label(), "Not Connected");
        assert_eq!(TrayStatus::Mounting.label(), "Mounting...");
        assert_eq!(TrayStatus::Syncing.label(), "Syncing...");
        assert_eq!(TrayStatus::Synced.label(), "Synced");
        assert_eq!(TrayStatus::Offline.label(), "Offline");
        assert_eq!(TrayStatus::Error("disk full".into()).label(), "Error");
        assert_eq!(TrayStatus::WriteParked.label(), "Upload Failed");
    }

    #[test]
    fn test_is_connected() {
        assert!(!TrayStatus::NotConnected.is_connected());
        assert!(!TrayStatus::Mounting.is_connected());
        assert!(TrayStatus::Syncing.is_connected());
        assert!(TrayStatus::Synced.is_connected());
        assert!(TrayStatus::Offline.is_connected());
        assert!(!TrayStatus::Error("oops".into()).is_connected());
        // WriteParked is authenticated + mounted: stays connected so Logout remains enabled.
        assert!(TrayStatus::WriteParked.is_connected());
    }
}
