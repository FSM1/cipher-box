//! Host seams — the trait contracts a host implements (blueprint/engine.md
//! "Host seams").
//!
//! The seven [`SeamTypes`] name the capabilities a host must supply, injected as
//! a constructor argument via [`SeamSet`]. [`RetireLedger`] and [`Mailbox`] are
//! the exceptions that prove the shape: the same trait contract, with a
//! conformance kit of its own, but the engine ships the implementation
//! ([`StagingRetireLedger`](crate::net::StagingRetireLedger) over the staging
//! store; [`ApiClient`](crate::api::ApiClient) over the [`Http`] seam) — a host
//! swaps one in only if it has a better backing to offer.
//!
//! Traits move opaque bytes and events — no seam holds logic, no domain type
//! leaks into a seam; the engine owns all interpretation.
//!
//! Determinism is injected: wall clock and timers come only from
//! [`Scheduler`], entropy only from [`crate::entropy::Entropy`]. Engine logic
//! never calls a clock or RNG directly.

mod credential_store;
mod floor_store;
mod http;
mod live;
mod mailbox;
mod record_transport;
mod retire_ledger;
mod scheduler;
mod snapshot_cache;
mod staging_store;

pub use credential_store::CredentialStore;
pub use floor_store::{
    CONTACT_LABEL_LEN, ContactLabel, FloorNamespace, FloorRaise, FloorStore, OWNER_TAG_LEN,
    OwnerScopedFloorStore, SharerScopedFloorStore,
};
pub use http::{
    CappedFetchError, Http, HttpCredentials, HttpMethod, HttpRequest, HttpResponse, InvalidBearer,
    bearer_header, check_bearer,
};
// The header name is an engine-internal spelling: a host implements the
// transport, it never builds a bearer.
pub(crate) use http::AUTHORIZATION;
// An engine-internal adapter over three of the seams, not a host contract.
pub(crate) use live::LiveSeam;
pub use mailbox::{Mailbox, MailboxItem};
// Wire-shape predicates the API DTO fixes; a host states no policy of its own.
pub(crate) use mailbox::{is_unreserved_1_128, item_id_is_legal};
pub use record_transport::{EndpointId, RecordTransport};
pub use retire_ledger::{OwedPage, OwedRetire, OwingRecord, RetireLedger};
pub use scheduler::{BoxedTask, Scheduler, UnixMillis};
pub use snapshot_cache::SnapshotCache;
pub use staging_store::{OpId, StagingStore};

use core::fmt;

/// Error returned by a seam implementation.
///
/// Deliberately opaque at this layer: a seam failure is a host-side I/O or
/// availability problem, never a trust decision — trust classification
/// happens in the engine (adoption gate, floor law). The message exists for
/// diagnostics only and must never carry key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeamError {
    message: String,
}

impl SeamError {
    /// Builds a seam error from a diagnostic message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The diagnostic message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for SeamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "seam error: {}", self.message)
    }
}

impl std::error::Error for SeamError {}

/// Result alias used by every seam method.
pub type SeamResult<T> = Result<T, SeamError>;

/// The type family binding one host's seven concrete seam implementations.
///
/// A host (web worker realm, desktop process, the test kit) implements this
/// trait once, naming its concrete type for every seam. Collapsing the seven
/// generics into one type parameter keeps [`SeamSet`] and
/// [`crate::facade::Engine`] signatures readable while preserving full
/// static dispatch — no boxing, no `Send` assumptions, so the same engine
/// compiles natively and to WASM.
pub trait SeamTypes {
    /// Durable floor storage ([`FloorStore`]).
    type FloorStore: FloorStore;
    /// Dumb `/routing/v1` byte mover ([`RecordTransport`]). `Clone + 'static`
    /// because the publish port hands a handle to the background re-PUT it
    /// spawns on the scheduler.
    type RecordTransport: RecordTransport + Clone + 'static;
    /// Plain HTTP ([`Http`]).
    type Http: Http;
    /// Timers, background tasks, wall clock ([`Scheduler`]). `Clone + 'static`
    /// for the same reason as [`RecordTransport`](Self::RecordTransport): the
    /// spawned task owns a handle of its own.
    type Scheduler: Scheduler + Clone + 'static;
    /// Durable op queue and staged bytes ([`StagingStore`]).
    type StagingStore: StagingStore;
    /// Durable last-known-good cache ([`SnapshotCache`]).
    type SnapshotCache: SnapshotCache;
    /// Refresh-token persistence ([`CredentialStore`]).
    type CredentialStore: CredentialStore;
}

/// The whole seam set, taken by the engine constructor in one piece.
///
/// Field-struct construction is the compile-time completeness gate
/// (blueprint/engine.md doctrine, #26 D8): omitting any seam is a missing
/// struct field — a compile error, not a silent behavior gap. There are no
/// optional seams and no defaults.
pub struct SeamSet<T: SeamTypes> {
    /// Durable monotonic-max floors; fail-closed regression rejection. Wrapped
    /// so every key is namespaced by the identity the engine starts under —
    /// two accounts on one device share a store but never a floor
    /// ([`OwnerScopedFloorStore`]).
    pub floor_store: OwnerScopedFloorStore<T::FloorStore>,
    /// GET/PUT of opaque signed record bytes against the endpoint set.
    pub record_transport: T::RecordTransport,
    /// HTTP for the API client, trustless gateway, and BYO providers.
    pub http: T::Http,
    /// Timers, background task execution, wall clock.
    pub scheduler: T::Scheduler,
    /// Durable op queue plus staged upload bytes.
    pub staging_store: T::StagingStore,
    /// Durable last-known-good record/metadata cache, ciphertext-only.
    pub snapshot_cache: T::SnapshotCache,
    /// Refresh-token persistence.
    pub credential_store: T::CredentialStore,
}
