//! Desktop [`RecordTransport`]: a `reqwest` `/routing/v1` byte mover.

use core::time::Duration;

use cipherbox_engine::seams::{EndpointId, RecordTransport, SeamError, SeamResult};

/// IPFS delegated-routing content type for a signed IPNS record.
const IPNS_RECORD_CONTENT_TYPE: &str = "application/vnd.ipfs.ipns-record";

fn over_cap(observed: usize, limit: usize) -> SeamError {
    SeamError::new(format!(
        "record_transport get body: {observed} bytes exceeds the {limit}-byte cap"
    ))
}

/// Dumb `/routing/v1` byte mover over `reqwest` (blueprint/engine.md
/// "RecordTransport", desktop column).
///
/// GET/PUT of opaque signed record bytes against a configured endpoint set;
/// it moves bytes and nothing else — the engine owns IPNS end-to-end (core
/// signs and verifies, fan-out, CAS, and every trust decision live above
/// this seam). Each [`EndpointId`] is the endpoint's base URL; a record for
/// `routing_key` is addressed at `<base>/routing/v1/ipns/<routing_key>`. An
/// absent record GETs as `None` (HTTP 404), never an error.
#[derive(Debug, Clone)]
pub struct ReqwestRecordTransport {
    client: reqwest::Client,
    endpoints: Vec<EndpointId>,
}

impl ReqwestRecordTransport {
    /// Builds a transport over the given `/routing/v1` base URLs (CipherBox
    /// someguy plus at least one independent public endpoint, #23 D1). The
    /// [`EndpointId`] of each endpoint is its base URL.
    ///
    /// # Panics
    /// Panics if `base_urls` is empty — the endpoint set must never be empty
    /// (the seam contract), and an empty set is a host misconfiguration, not
    /// a runtime condition.
    pub fn new(base_urls: impl IntoIterator<Item = String>) -> SeamResult<Self> {
        let endpoints: Vec<EndpointId> = base_urls.into_iter().map(EndpointId::new).collect();
        assert!(
            !endpoints.is_empty(),
            "RecordTransport endpoint set must not be empty"
        );
        // `/routing/v1` records are small and directly addressed: bound both
        // the handshake and the whole request so a stalled public endpoint
        // cannot hang fan-out, and follow no redirects — direct addressing
        // needs none, and refusing them closes an SSRF-shaped vector from an
        // untrusted public endpoint. `with_client` callers own their policy.
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| SeamError::new(format!("record_transport client build: {err}")))?;
        Ok(Self { client, endpoints })
    }

    /// Builds a transport over a caller-supplied `reqwest` client.
    ///
    /// # Panics
    /// Panics if `base_urls` is empty (see [`ReqwestRecordTransport::new`]).
    pub fn with_client(
        client: reqwest::Client,
        base_urls: impl IntoIterator<Item = String>,
    ) -> Self {
        let endpoints: Vec<EndpointId> = base_urls.into_iter().map(EndpointId::new).collect();
        assert!(
            !endpoints.is_empty(),
            "RecordTransport endpoint set must not be empty"
        );
        Self { client, endpoints }
    }

    fn record_url(endpoint: &EndpointId, routing_key: &str) -> String {
        format!(
            "{}/routing/v1/ipns/{routing_key}",
            endpoint.0.trim_end_matches('/')
        )
    }
}

impl RecordTransport for ReqwestRecordTransport {
    fn endpoints(&self) -> Vec<EndpointId> {
        self.endpoints.clone()
    }

    async fn get_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        max_bytes: usize,
    ) -> SeamResult<Option<Vec<u8>>> {
        let mut response = self
            .client
            .get(Self::record_url(endpoint, routing_key))
            .header(reqwest::header::ACCEPT, IPNS_RECORD_CONTENT_TYPE)
            .send()
            .await
            .map_err(|err| SeamError::new(format!("record_transport get: {err}")))?;

        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(SeamError::new(format!(
                "record_transport get: status {}",
                status.as_u16()
            )));
        }

        // Reject a body that declares itself over the cap before reading a byte;
        // a missing or lying Content-Length is still bounded by the drain below.
        if let Some(declared) = response.content_length() {
            if declared > max_bytes as u64 {
                return Err(over_cap(declared as usize, max_bytes));
            }
        }
        let mut record = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| SeamError::new(format!("record_transport get body: {err}")))?
        {
            if record.len() + chunk.len() > max_bytes {
                return Err(over_cap(record.len() + chunk.len(), max_bytes));
            }
            record.extend_from_slice(&chunk);
        }
        Ok(Some(record))
    }

    async fn put_record(
        &self,
        endpoint: &EndpointId,
        routing_key: &str,
        record: &[u8],
    ) -> SeamResult<()> {
        let response = self
            .client
            .put(Self::record_url(endpoint, routing_key))
            .header(reqwest::header::CONTENT_TYPE, IPNS_RECORD_CONTENT_TYPE)
            .body(record.to_vec())
            .send()
            .await
            .map_err(|err| SeamError::new(format!("record_transport put: {err}")))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(SeamError::new(format!(
                "record_transport put: status {}",
                response.status().as_u16()
            )))
        }
    }
}
