//! The operation core's failure vocabulary. Semantic, not numeric: each host
//! adapter maps these onto its own protocol (errno, NTSTATUS).

use core::fmt;

use cipherbox_engine::EngineError;
/// Which budget a write exceeded, in the engine's own vocabulary. Choosing the
/// errno stays the adapter's call, but not a judgement call:
/// [`OverBudgetCause::budget`] decides it.
pub use cipherbox_engine::{OverBudgetCause, RefusedBudget};

use crate::name::NameError;

/// Why a vfs operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VfsError {
    /// No such node.
    NotFound,
    /// The operation named a file where it needed a folder.
    NotADirectory,
    /// The operation named a folder where it needed a file.
    IsADirectory,
    /// A folder with children cannot be removed.
    NotEmpty,
    /// A node of that name already exists under the parent.
    AlreadyExists,
    /// The operation is structurally impossible — moving a folder inside
    /// itself, which would detach the whole subtree from the root, or writing a
    /// file past the size one version can represent.
    Invalid,
    /// The name is not admissible.
    InvalidName(NameError),
    /// The handle is not open.
    BadHandle,
    /// A write exceeded a storage budget.
    OverBudget(OverBudgetCause),
    /// A journal-time refusal ([`EngineError::ScopeExitRefused`]). Fail-closed
    /// and never retried; an adapter maps it to its EIO-class code.
    Refused {
        /// The refusal classification; never key material.
        message: String,
    },
    /// A fail-closed trust verdict below the facade. Never retried, never
    /// rendered, and never conflated with staleness (security rule 6).
    TrustViolation {
        /// The verdict classification; never key material.
        message: String,
    },
    /// The engine could not serve the read right now. Availability, retryable.
    Unavailable {
        /// Diagnostic message; never key material.
        message: String,
    },
    /// A host-local failure: durable-queue I/O, or a facade call the mount had
    /// no business making.
    Internal {
        /// Diagnostic message; never key material.
        message: String,
    },
}

impl From<EngineError> for VfsError {
    /// Exhaustive by construction: no wildcard arm, so a new `EngineError`
    /// variant is a compile error here rather than a fail-closed verdict that
    /// silently degrades to [`Internal`](VfsError::Internal).
    fn from(error: EngineError) -> Self {
        match error {
            EngineError::UnknownNode => VfsError::NotFound,
            EngineError::NotAFolder => VfsError::NotADirectory,
            EngineError::NotAFile => VfsError::IsADirectory,
            EngineError::TrustViolation { message } | EngineError::ColdStart { message } => {
                VfsError::TrustViolation { message }
            }
            EngineError::OverBudget { cause, .. } => VfsError::OverBudget(cause),
            EngineError::ScopeExitRefused { message } => VfsError::Refused { message },
            EngineError::ContentUnavailable { message }
            | EngineError::RefreshFailed { message } => VfsError::Unavailable { message },
            // Retryable once the vault settings resolve or are saved again, and
            // not a storage verdict: the device has room, the engine simply does
            // not know where the member wants the bytes.
            error @ EngineError::NoPlacement { .. } => VfsError::Unavailable {
                message: error.to_string(),
            },
            // Retryable once the mount closes a stream, not a storage verdict.
            error @ EngineError::TooManyStreams => VfsError::Unavailable {
                message: error.to_string(),
            },
            EngineError::UnsupportedContentFormat { version } => VfsError::Unavailable {
                message: format!("unsupported content format version {version}"),
            },
            // Past the flat-DAG ceiling: no amount of free space stores a file
            // this large as one version, so it is not a budget verdict.
            EngineError::ContentTooLarge { .. } => VfsError::Invalid,
            EngineError::MalformedInput { .. } => VfsError::Invalid,
            EngineError::Seam { message }
            | EngineError::Entropy { message }
            | EngineError::Auth { message } => VfsError::Internal { message },
            // A write handle that lost track of its own file is a broken caller
            // contract on the mount's side, never a user-visible storage verdict.
            error @ (EngineError::NotStarted
            | EngineError::AlreadyStarted
            | EngineError::InvalidSecret
            | EngineError::ContentSizeMismatch { .. }
            | EngineError::UnknownWriteHandle
            | EngineError::UnknownStreamHandle
            | EngineError::ContentKeySealFailed { .. }
            | EngineError::TooLateToCancel { .. }
            | EngineError::NotAnUpload { .. }
            | EngineError::Unimplemented { .. }) => VfsError::Internal {
                message: error.to_string(),
            },
        }
    }
}

impl From<NameError> for VfsError {
    fn from(error: NameError) -> Self {
        VfsError::InvalidName(error)
    }
}

impl fmt::Display for VfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VfsError::NotFound => f.write_str("no such node"),
            VfsError::NotADirectory => f.write_str("not a directory"),
            VfsError::IsADirectory => f.write_str("is a directory"),
            VfsError::NotEmpty => f.write_str("directory not empty"),
            VfsError::AlreadyExists => f.write_str("already exists"),
            VfsError::Invalid => f.write_str("invalid operation"),
            VfsError::InvalidName(reason) => write!(f, "invalid name: {reason:?}"),
            VfsError::BadHandle => f.write_str("bad file handle"),
            VfsError::OverBudget(cause) => write!(f, "over budget: {cause:?}"),
            VfsError::Refused { message } => write!(f, "refused: {message}"),
            VfsError::TrustViolation { message } => write!(f, "trust violation: {message}"),
            VfsError::Unavailable { message } => write!(f, "unavailable: {message}"),
            VfsError::Internal { message } => write!(f, "internal: {message}"),
        }
    }
}

impl std::error::Error for VfsError {}

#[cfg(test)]
mod tests {
    use cipherbox_engine::seams::OpId;

    use super::*;

    #[test]
    fn node_shape_errors_map_to_their_posix_counterparts() {
        assert_eq!(VfsError::from(EngineError::UnknownNode), VfsError::NotFound);
        assert_eq!(
            VfsError::from(EngineError::NotAFolder),
            VfsError::NotADirectory
        );
        assert_eq!(
            VfsError::from(EngineError::NotAFile),
            VfsError::IsADirectory
        );
    }

    #[test]
    fn every_fail_closed_verdict_stays_a_trust_violation() {
        for error in [
            EngineError::TrustViolation {
                message: "rejected child record".into(),
            },
            EngineError::ColdStart {
                message: "regressed floor".into(),
            },
        ] {
            assert!(
                matches!(
                    VfsError::from(error.clone()),
                    VfsError::TrustViolation { .. }
                ),
                "{error} must never degrade to availability"
            );
        }
    }

    #[test]
    fn availability_failures_stay_availability() {
        for error in [
            EngineError::ContentUnavailable {
                message: "no reachable source".into(),
            },
            EngineError::RefreshFailed {
                message: "no endpoint served a record this pass could adopt".into(),
            },
            EngineError::UnsupportedContentFormat { version: 9 },
        ] {
            assert!(matches!(
                VfsError::from(error),
                VfsError::Unavailable { .. }
            ));
        }
    }

    /// A full device and a full account are different errnos to the user, so
    /// the cause has to survive the crossing.
    #[test]
    fn each_budget_keeps_its_own_cause() {
        for cause in [
            OverBudgetCause::StagingLimit,
            OverBudgetCause::DeviceFull,
            OverBudgetCause::StagingBacklog,
            OverBudgetCause::StorageUnmeasured,
            OverBudgetCause::AccountQuota,
            OverBudgetCause::TooManyWrites,
        ] {
            assert_eq!(
                VfsError::from(EngineError::OverBudget {
                    cause,
                    requested: 900,
                    available: 100,
                }),
                VfsError::OverBudget(cause)
            );
        }
    }

    /// The whole cause set against the errno axis, so no adapter re-decides it.
    #[test]
    fn only_the_account_quota_is_an_account_budget() {
        for cause in [
            OverBudgetCause::StagingLimit,
            OverBudgetCause::DeviceFull,
            OverBudgetCause::StagingBacklog,
            OverBudgetCause::StorageUnmeasured,
            OverBudgetCause::TooManyWrites,
        ] {
            assert_eq!(cause.budget(), RefusedBudget::Device, "{cause:?}");
        }
        assert_eq!(
            OverBudgetCause::AccountQuota.budget(),
            RefusedBudget::Account
        );
    }

    /// An adapter that mapped this to [`VfsError::Internal`] would report a
    /// host fault for a verdict the user must act on.
    #[test]
    fn a_journal_time_refusal_is_its_own_class() {
        assert_eq!(
            VfsError::from(EngineError::ScopeExitRefused {
                message: "out of scope".into(),
            }),
            VfsError::Refused {
                message: "out of scope".into(),
            }
        );
    }

    #[test]
    fn host_side_failures_are_internal_and_never_trust_verdicts() {
        for error in [
            EngineError::NotStarted,
            EngineError::AlreadyStarted,
            EngineError::InvalidSecret,
            EngineError::TooLateToCancel { op_id: OpId(1) },
            EngineError::NotAnUpload { op_id: OpId(2) },
            EngineError::Unimplemented { command: "grant" },
            EngineError::Seam {
                message: "fsync failed".into(),
            },
            EngineError::Entropy {
                message: "no entropy".into(),
            },
            EngineError::Auth {
                message: "401".into(),
            },
        ] {
            assert!(
                matches!(VfsError::from(error), VfsError::Internal { .. }),
                "a host-local failure must not read as a trust verdict"
            );
        }
    }
}
