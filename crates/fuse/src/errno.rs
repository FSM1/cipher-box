//! The one `VfsError` → errno table, shared by every unix mount technology.

use crate::error::{RefusedBudget, VfsError};
use crate::name::NameError;

/// The errno a kernel gets for `error`.
///
/// Three classes are deliberately distinct, because the user acts on each
/// differently (blueprint/desktop.md "statfs", "Conflicts, dead letters, and
/// rotation"):
///
/// - a storage refusal names *which* budget refused — `ENOSPC` for the device,
///   `EDQUOT` for the hosted account, never both collapsed into "disk full";
/// - a fail-closed verdict — a trust violation or a journal-time refusal — is
///   `EIO`, terminal, with the tray carrying the explanation;
/// - an availability failure is `EAGAIN`: the same operation may succeed once
///   the content resolves, and it must never read as the terminal `EIO` class.
pub fn errno_of(error: &VfsError) -> i32 {
    match error {
        VfsError::NotFound => libc::ENOENT,
        VfsError::NotADirectory => libc::ENOTDIR,
        VfsError::IsADirectory => libc::EISDIR,
        VfsError::NotEmpty => libc::ENOTEMPTY,
        VfsError::AlreadyExists => libc::EEXIST,
        VfsError::Invalid => libc::EINVAL,
        VfsError::InvalidName(reason) => name_errno(*reason),
        VfsError::BadHandle => libc::EBADF,
        VfsError::OverBudget(cause) => match cause.budget() {
            RefusedBudget::Device => libc::ENOSPC,
            RefusedBudget::Account => libc::EDQUOT,
        },
        VfsError::Refused { .. } | VfsError::TrustViolation { .. } => libc::EIO,
        VfsError::Unavailable { .. } => libc::EAGAIN,
        VfsError::Internal { .. } => libc::EIO,
    }
}

/// Length is the one refusal POSIX gives its own code; every other
/// inadmissible name is a malformed argument.
fn name_errno(reason: NameError) -> i32 {
    match reason {
        NameError::TooLong => libc::ENAMETOOLONG,
        NameError::Empty
        | NameError::DotEntry
        | NameError::Separator
        | NameError::Control
        | NameError::DeceptiveCharacter
        | NameError::ReservedCharacter
        | NameError::TrailingDotOrSpace
        | NameError::ReservedDevice
        | NameError::PlatformJunk => libc::EINVAL,
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_engine::OverBudgetCause;

    use super::*;

    /// The whole vocabulary against its errno, so a new variant cannot reach a
    /// kernel as whatever the last arm happened to be.
    #[test]
    fn every_verdict_maps_to_its_named_errno() {
        let table: &[(VfsError, i32)] = &[
            (VfsError::NotFound, libc::ENOENT),
            (VfsError::NotADirectory, libc::ENOTDIR),
            (VfsError::IsADirectory, libc::EISDIR),
            (VfsError::NotEmpty, libc::ENOTEMPTY),
            (VfsError::AlreadyExists, libc::EEXIST),
            (VfsError::Invalid, libc::EINVAL),
            (
                VfsError::InvalidName(NameError::TooLong),
                libc::ENAMETOOLONG,
            ),
            (VfsError::InvalidName(NameError::Separator), libc::EINVAL),
            (VfsError::BadHandle, libc::EBADF),
            (
                VfsError::OverBudget(OverBudgetCause::DeviceFull),
                libc::ENOSPC,
            ),
            (
                VfsError::OverBudget(OverBudgetCause::AccountQuota),
                libc::EDQUOT,
            ),
            (
                VfsError::Refused {
                    message: "out of scope".to_owned(),
                },
                libc::EIO,
            ),
            (
                VfsError::TrustViolation {
                    message: "regressed floor".to_owned(),
                },
                libc::EIO,
            ),
            (
                VfsError::Unavailable {
                    message: "no reachable source".to_owned(),
                },
                libc::EAGAIN,
            ),
            (
                VfsError::Internal {
                    message: "fsync failed".to_owned(),
                },
                libc::EIO,
            ),
        ];
        for (error, expected) in table {
            assert_eq!(errno_of(error), *expected, "{error}");
        }
    }

    /// Every name refusal, so a new admission rule cannot silently answer a
    /// kernel with the errno of a different one.
    #[test]
    fn every_name_refusal_maps_to_its_named_errno() {
        let table: &[(NameError, i32)] = &[
            (NameError::Empty, libc::EINVAL),
            (NameError::TooLong, libc::ENAMETOOLONG),
            (NameError::DotEntry, libc::EINVAL),
            (NameError::Separator, libc::EINVAL),
            (NameError::Control, libc::EINVAL),
            (NameError::DeceptiveCharacter, libc::EINVAL),
            (NameError::ReservedCharacter, libc::EINVAL),
            (NameError::TrailingDotOrSpace, libc::EINVAL),
            (NameError::ReservedDevice, libc::EINVAL),
            (NameError::PlatformJunk, libc::EINVAL),
        ];
        for (reason, expected) in table {
            assert_eq!(name_errno(*reason), *expected, "{reason:?}");
        }
    }

    /// The distinction the blueprint puts on this axis: a full device tells the
    /// user to free space here, a hosted-quota refusal tells them to buy or
    /// free space there. Collapsing them sends them to the wrong machine.
    #[test]
    fn a_device_budget_and_an_account_budget_are_different_errnos() {
        for cause in [
            OverBudgetCause::StagingLimit,
            OverBudgetCause::DeviceFull,
            OverBudgetCause::StagingBacklog,
            OverBudgetCause::StorageUnmeasured,
            OverBudgetCause::TooManyWrites,
        ] {
            assert_eq!(
                errno_of(&VfsError::OverBudget(cause)),
                libc::ENOSPC,
                "{cause:?}"
            );
        }
        assert_eq!(
            errno_of(&VfsError::OverBudget(OverBudgetCause::AccountQuota)),
            libc::EDQUOT
        );
    }

    /// Relational, not a second copy of the table above: the two classes must
    /// stay apart however either value moves (security rule 6).
    #[test]
    fn availability_never_arrives_as_the_fail_closed_code() {
        let unavailable = errno_of(&VfsError::Unavailable {
            message: "no endpoint served a record this pass could adopt".to_owned(),
        });
        for terminal in [
            VfsError::TrustViolation {
                message: "rejected child record".to_owned(),
            },
            VfsError::Refused {
                message: "rotation impossible".to_owned(),
            },
        ] {
            assert_ne!(errno_of(&terminal), unavailable, "{terminal}");
        }
    }
}
