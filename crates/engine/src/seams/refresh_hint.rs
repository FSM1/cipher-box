//! `RefreshHintSource` — host events forcing an immediate tick
//! (blueprint/engine.md).

/// One refresh hint. Carries no payload in v2.0: a hint only ever means
/// "run an immediate focus-window tick now".
///
/// The designed-for push overlay (#33 D1 — API WebSocket hints, desktop
/// PubSub) extends this type behind the same seam when it lands; hosts and
/// the engine already treat hints as events, so richer payloads are
/// additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RefreshHint;

/// Host-event stream that forces an immediate sync tick.
///
/// Web: UI navigation, tab-visibility regain, `online` reconnect, cross-tab
/// focus hints. Desktop: FUSE-op TTL checks, reconnect. Hints are
/// best-effort accelerators — losing one costs staleness bounded by the
/// poll cadence, never correctness — so no conformance kit ships for this
/// seam: it has no durable semantics, and its events are host-driven.
pub trait RefreshHintSource {
    /// Waits for the next hint; `None` once the source is closed for good
    /// (host shutdown). The engine treats `None` as end-of-stream and stops
    /// listening.
    async fn next_hint(&mut self) -> Option<RefreshHint>;
}
