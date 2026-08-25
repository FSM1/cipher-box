//! The one `VfsError` → NTSTATUS table, for the WinFsp backend.
//!
//! The unix sibling is [`crate::errno`]; the two are separate tables because
//! the codes are, but they answer the same vocabulary and split it along the
//! same three classes. Portable rather than `cfg(windows)`: the values are
//! constants from the NT status space, not an API call, so the mapping is
//! gated on every leg that runs this crate's tests rather than only on the
//! Windows one.

use crate::error::{RefusedBudget, VfsError};
use crate::name::NameError;

/// An NT status code, as WinFsp returns one.
pub type NtStatus = i32;

// The NT status space, from `ntstatus.h`. Named here rather than pulled from a
// Windows-only binding so the table compiles — and is tested — on every host.
const STATUS_OBJECT_NAME_NOT_FOUND: NtStatus = 0xC000_0034_u32 as i32;
const STATUS_NOT_A_DIRECTORY: NtStatus = 0xC000_0103_u32 as i32;
const STATUS_FILE_IS_A_DIRECTORY: NtStatus = 0xC000_00BA_u32 as i32;
const STATUS_DIRECTORY_NOT_EMPTY: NtStatus = 0xC000_0101_u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: NtStatus = 0xC000_0035_u32 as i32;
const STATUS_INVALID_PARAMETER: NtStatus = 0xC000_000D_u32 as i32;
const STATUS_OBJECT_NAME_INVALID: NtStatus = 0xC000_0033_u32 as i32;
const STATUS_NAME_TOO_LONG: NtStatus = 0xC000_0106_u32 as i32;
const STATUS_INVALID_HANDLE: NtStatus = 0xC000_0008_u32 as i32;
const STATUS_DISK_FULL: NtStatus = 0xC000_007F_u32 as i32;
const STATUS_QUOTA_EXCEEDED: NtStatus = 0xC000_0044_u32 as i32;
const STATUS_DATA_ERROR: NtStatus = 0xC000_003E_u32 as i32;
const STATUS_RETRY: NtStatus = 0xC000_022D_u32 as i32;

/// The NT status a WinFsp caller gets for `error`.
///
/// The same three classes the errno table keeps apart, because the user acts on
/// each differently (blueprint/desktop.md "statfs", "Conflicts, dead letters,
/// and rotation"):
///
/// - a storage refusal names *which* budget refused — `STATUS_DISK_FULL` for
///   the device, `STATUS_QUOTA_EXCEEDED` for the hosted account, never both
///   collapsed into "disk full";
/// - a fail-closed verdict — a trust violation or a journal-time refusal — is
///   `STATUS_DATA_ERROR`, terminal, with the tray carrying the explanation;
/// - an availability failure is `STATUS_RETRY`: the same operation may succeed
///   once the content resolves, and it must never read as the terminal class.
pub fn ntstatus_of(error: &VfsError) -> NtStatus {
    match error {
        VfsError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        VfsError::NotADirectory => STATUS_NOT_A_DIRECTORY,
        VfsError::IsADirectory => STATUS_FILE_IS_A_DIRECTORY,
        VfsError::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        VfsError::AlreadyExists => STATUS_OBJECT_NAME_COLLISION,
        VfsError::Invalid => STATUS_INVALID_PARAMETER,
        VfsError::InvalidName(reason) => name_status(*reason),
        VfsError::BadHandle => STATUS_INVALID_HANDLE,
        VfsError::OverBudget(cause) => match cause.budget() {
            RefusedBudget::Device => STATUS_DISK_FULL,
            RefusedBudget::Account => STATUS_QUOTA_EXCEEDED,
        },
        VfsError::Refused { .. } | VfsError::TrustViolation { .. } => STATUS_DATA_ERROR,
        VfsError::Unavailable { .. } => STATUS_RETRY,
        VfsError::Internal { .. } => STATUS_DATA_ERROR,
    }
}

/// Length is the one refusal NT gives its own code; every other inadmissible
/// name is a malformed name rather than a malformed argument, which is the
/// distinction Win32 surfaces as `ERROR_INVALID_NAME`.
fn name_status(reason: NameError) -> NtStatus {
    match reason {
        NameError::TooLong => STATUS_NAME_TOO_LONG,
        NameError::Empty
        | NameError::DotEntry
        | NameError::Separator
        | NameError::Control
        | NameError::DeceptiveCharacter
        | NameError::ReservedCharacter
        | NameError::TrailingDotOrSpace
        | NameError::ReservedDevice
        | NameError::PlatformJunk => STATUS_OBJECT_NAME_INVALID,
    }
}

#[cfg(test)]
mod tests {
    use cipherbox_engine::OverBudgetCause;

    use super::*;

    /// The whole vocabulary against its status, so a new variant cannot reach
    /// WinFsp as whatever the last arm happened to be.
    #[test]
    fn every_verdict_maps_to_its_named_status() {
        let table: &[(VfsError, NtStatus)] = &[
            (VfsError::NotFound, STATUS_OBJECT_NAME_NOT_FOUND),
            (VfsError::NotADirectory, STATUS_NOT_A_DIRECTORY),
            (VfsError::IsADirectory, STATUS_FILE_IS_A_DIRECTORY),
            (VfsError::NotEmpty, STATUS_DIRECTORY_NOT_EMPTY),
            (VfsError::AlreadyExists, STATUS_OBJECT_NAME_COLLISION),
            (VfsError::Invalid, STATUS_INVALID_PARAMETER),
            (
                VfsError::InvalidName(NameError::TooLong),
                STATUS_NAME_TOO_LONG,
            ),
            (
                VfsError::InvalidName(NameError::ReservedDevice),
                STATUS_OBJECT_NAME_INVALID,
            ),
            (VfsError::BadHandle, STATUS_INVALID_HANDLE),
            (
                VfsError::OverBudget(OverBudgetCause::DeviceFull),
                STATUS_DISK_FULL,
            ),
            (
                VfsError::OverBudget(OverBudgetCause::AccountQuota),
                STATUS_QUOTA_EXCEEDED,
            ),
            (
                VfsError::Refused {
                    message: "out of scope".to_owned(),
                },
                STATUS_DATA_ERROR,
            ),
            (
                VfsError::TrustViolation {
                    message: "regressed floor".to_owned(),
                },
                STATUS_DATA_ERROR,
            ),
            (
                VfsError::Unavailable {
                    message: "no reachable source".to_owned(),
                },
                STATUS_RETRY,
            ),
            (
                VfsError::Internal {
                    message: "fsync failed".to_owned(),
                },
                STATUS_DATA_ERROR,
            ),
        ];
        for (error, expected) in table {
            assert_eq!(ntstatus_of(error), *expected, "{error}");
        }
    }

    /// Every name refusal, so a new admission rule cannot silently answer with
    /// the status of a different one.
    #[test]
    fn every_name_refusal_maps_to_its_named_status() {
        let table: &[(NameError, NtStatus)] = &[
            (NameError::Empty, STATUS_OBJECT_NAME_INVALID),
            (NameError::TooLong, STATUS_NAME_TOO_LONG),
            (NameError::DotEntry, STATUS_OBJECT_NAME_INVALID),
            (NameError::Separator, STATUS_OBJECT_NAME_INVALID),
            (NameError::Control, STATUS_OBJECT_NAME_INVALID),
            (NameError::DeceptiveCharacter, STATUS_OBJECT_NAME_INVALID),
            (NameError::ReservedCharacter, STATUS_OBJECT_NAME_INVALID),
            (NameError::TrailingDotOrSpace, STATUS_OBJECT_NAME_INVALID),
            (NameError::ReservedDevice, STATUS_OBJECT_NAME_INVALID),
            (NameError::PlatformJunk, STATUS_OBJECT_NAME_INVALID),
        ];
        for (reason, expected) in table {
            assert_eq!(name_status(*reason), *expected, "{reason:?}");
        }
    }

    /// A full device and a full account send the user to different machines,
    /// so the cause has to survive onto this axis too.
    #[test]
    fn a_device_budget_and_an_account_budget_are_different_statuses() {
        for cause in [
            OverBudgetCause::StagingLimit,
            OverBudgetCause::DeviceFull,
            OverBudgetCause::StagingBacklog,
            OverBudgetCause::StorageUnmeasured,
            OverBudgetCause::TooManyWrites,
        ] {
            assert_eq!(
                ntstatus_of(&VfsError::OverBudget(cause)),
                STATUS_DISK_FULL,
                "{cause:?}"
            );
        }
        assert_eq!(
            ntstatus_of(&VfsError::OverBudget(OverBudgetCause::AccountQuota)),
            STATUS_QUOTA_EXCEEDED
        );
    }

    /// Relational, not a second copy of the table above: the two classes must
    /// stay apart however either value moves (security rule 6).
    #[test]
    fn availability_never_arrives_as_the_fail_closed_status() {
        let unavailable = ntstatus_of(&VfsError::Unavailable {
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
            assert_ne!(ntstatus_of(&terminal), unavailable, "{terminal}");
        }
    }

    /// A status whose top two bits are not `11` is a success or an informational
    /// code: WinFsp would take it for an operation that worked, and the caller
    /// would read whatever the reply buffer happened to hold.
    #[test]
    fn every_refusal_is_an_error_severity_status() {
        for error in [
            VfsError::NotFound,
            VfsError::NotADirectory,
            VfsError::IsADirectory,
            VfsError::NotEmpty,
            VfsError::AlreadyExists,
            VfsError::Invalid,
            VfsError::InvalidName(NameError::TooLong),
            VfsError::InvalidName(NameError::Separator),
            VfsError::BadHandle,
            VfsError::OverBudget(OverBudgetCause::DeviceFull),
            VfsError::OverBudget(OverBudgetCause::AccountQuota),
            VfsError::Refused {
                message: "out of scope".to_owned(),
            },
            VfsError::TrustViolation {
                message: "regressed floor".to_owned(),
            },
            VfsError::Unavailable {
                message: "no reachable source".to_owned(),
            },
            VfsError::Internal {
                message: "fsync failed".to_owned(),
            },
        ] {
            let severity = (ntstatus_of(&error) as u32) >> 30;
            assert_eq!(severity, 0b11, "{error} must refuse, not succeed");
        }
    }
}
