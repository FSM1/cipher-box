//! The operation core's failure vocabulary. Semantic, not numeric: each host
//! adapter maps these onto its own protocol (errno, NTSTATUS).

use core::fmt;

use cipherbox_engine::EngineError;
/// Which budget a write exceeded, in the engine's own vocabulary. Which errno
/// each maps to is the adapter's call: `ENOSPC` for a full device, `EDQUOT` for
/// a full account.
pub use cipherbox_engine::OverBudgetCause;

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
            EngineError::ContentUnavailable { message } => VfsError::Unavailable { message },
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
            EngineError::UnsupportedContentFormat { version: 9 },
        ] {
            assert!(matches!(
                VfsError::from(error),
                VfsError::Unavailable { .. }
            ));
        }
    }

    /// A full device and a full account are different errnos to the user, so
    /// the cause has to survive the crossing (#867).
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
