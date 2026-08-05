//! `RecordTransport` — dumb `/routing/v1` byte mover (blueprint/engine.md).

use super::SeamResult;

/// Identifies one configured `/routing/v1` endpoint.
///
/// Opaque to the engine: it enumerates endpoints for fan-out GET / parallel
/// PUT bookkeeping and hands the token back to the transport, which alone
/// knows how to reach it (URL, embedded DHT node, …).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EndpointId(pub String);

impl EndpointId {
    /// Builds an endpoint identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Dumb `/routing/v1` byte mover: GET/PUT of opaque signed record bytes
/// against a configured endpoint set.
///
/// The engine owns IPNS end-to-end (#28 D2): core signs and verifies,
/// this seam only moves bytes. Fan-out across the endpoint set, CAS,
/// re-resolve confirmation, and every trust decision live in the engine —
/// a transport never inspects, caches, or reorders records.
///
/// The endpoint set is host configuration: CipherBox someguy plus at least
/// one independent public endpoint (#23 D1); a desktop embedded rust-libp2p
/// kad backend is designed-for behind this same trait (#23 D2).
pub trait RecordTransport {
    /// The configured endpoint set. Never empty; order is not significant.
    fn endpoints(&self) -> Vec<EndpointId>;

    /// GET the signed record bytes stored for `routing_key` at one endpoint;
    /// `None` when the endpoint holds no record for that key.
    ///
    /// `routing_key` is the exact `/routing/v1` path segment (the textual
    /// IPNS name); the transport must not interpret it beyond addressing.
    ///
    /// The endpoint set includes untrusted public endpoints, so the transport
    /// bounds the read at `max_bytes` while the body arrives, exactly as
    /// [`super::Http::send_capped`] does. An over-cap body is an `Err`: no
    /// record above the cap is adoptable, and fan-out treats the endpoint as
    /// having served nothing.
    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>>;

    /// PUT opaque signed record bytes for `routing_key` at one endpoint.
    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()>;
}
