//! The projection on a platform `crates/fuse` has no host adapter for. The
//! session runs, and the vault is reachable through this window and the web
//! app; nothing is projected as a filesystem.

use std::path::Path;

use cipherbox_engine::{Engine, Event};

use super::MountStatus;
use crate::engine::DesktopSeamTypes;

/// The refusal the window renders. A mount is not something a member can fix
/// here, so the line says what is missing rather than what to try.
const NO_ADAPTER: &str = "CipherBox does not mount your vault on this platform yet";

/// One decoded kernel request. There is no mount to decode one from.
pub enum KernelOp {}

/// The session's engine, held where a mounted platform holds an operation core.
pub struct Projection(Engine<DesktopSeamTypes>);

impl Projection {
    pub fn open(engine: Engine<DesktopSeamTypes>, _home_dir: &Path, _account_dir: &Path) -> Self {
        Self(engine)
    }

    pub fn engine_mut(&mut self) -> &mut Engine<DesktopSeamTypes> {
        &mut self.0
    }

    pub fn status(&self) -> MountStatus {
        MountStatus::refused(NO_ADAPTER)
    }

    pub async fn next_op(&mut self) -> KernelOp {
        core::future::pending().await
    }

    pub async fn answer(&mut self, op: KernelOp) {
        match op {}
    }

    pub async fn absorb(&mut self, _event: &Event) {}

    pub fn tear_down(self) {}
}
