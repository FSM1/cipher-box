//! The transport deadlines the engine puts on `HttpRequest::timeout_ms`.
//!
//! Policy, not engine logic, so it enters as a parameter rather than as module
//! constants (AGENTS.md "Code Generation Guidelines" rule 3). One carrier for
//! all five, so a host tuning one of them cannot leave the others behind.

/// Per-request deadlines, in milliseconds, one field per transport leg.
///
/// [`Default`] is the shipped policy; a host that measures a slower network
/// tunes the legs it needs and keeps the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlinePolicy {
    /// A BYO-provider reachability probe: an unresponsive endpoint must read as
    /// unreachable rather than hang the settings flow.
    pub probe_ms: u64,
    /// One block placed on a member's own provider. Longer than the probe:
    /// this one moves a whole block.
    pub placement_ms: u64,
    /// One leaf-block GET. A seek issues one per leaf against sources of
    /// unknown quality, so a stalled gateway must fail over.
    pub block_fetch_ms: u64,
    /// An API control call: small JSON round trips must not park a UI flow.
    pub control_ms: u64,
    /// An API upload. A content block legitimately moves megabytes on a slow
    /// uplink, so it cannot share the control bound.
    pub transfer_ms: u64,
}

impl Default for DeadlinePolicy {
    fn default() -> Self {
        Self {
            probe_ms: 10_000,
            placement_ms: 60_000,
            block_fetch_ms: 30_000,
            control_ms: 10_000,
            transfer_ms: 120_000,
        }
    }
}
