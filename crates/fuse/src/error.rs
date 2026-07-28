//! The operation core's failure vocabulary. Semantic, not numeric: each host
//! adapter maps these onto its own protocol (errno, NTSTATUS).

use core::fmt;

use cipherbox_engine::EngineError;

use crate::name::NameError;

/// Which budget a write exceeded. The two are different facts about the world
/// and different errnos to the user: a full device is not a full account.
/// Which errno each maps to is the adapter's call (#867).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverBudgetCause {
    /// This device's offline staging budget is exhausted.
    DeviceStaging,
    /// The account's hosted storage quota refused the write.
    AccountQuota,
}

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
    /// itself, which would detach the whole subtree from the root.
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
            EngineError::ContentUnavailable { message } => VfsError::Unavailable { message },
            EngineError::UnsupportedContentFormat { version } => VfsError::Unavailable {
                message: format!("unsupported content format version {version}"),
            },
            EngineError::Seam { message }
            | EngineError::Entropy { message }
            | EngineError::Auth { message } => VfsError::Internal { message },
            error @ (EngineError::NotStarted
            | EngineError::AlreadyStarted
            | EngineError::InvalidSecret
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

    #[test]
    fn host_side_failures_are_internal_and_never_trust_verdicts() {
        for error in [
            EngineError::NotStarted,
            EngineError::AlreadyStarted,
            EngineError::InvalidSecret,
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
