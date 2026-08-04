//! Endpoint-set fan-out primitives shared by the resolve, publish, and liveness
//! paths (blueprint/engine.md "Resolve/publish pipeline").
//!
//! The engine owns IPNS end-to-end over dumb `/routing/v1` transports (#28 D2):
//! core signs and verifies, the [`RecordTransport`] seam only moves bytes, and
//! every decision — which endpoint's copy is freshest, when a PUT has succeeded,
//! which endpoints still need a retry — lives here.

use core::future::poll_fn;
use core::task::Poll;

use cipherbox_core::ipns::{IpnsName, IpnsRecord, VerifiedRecord};

use crate::seams::{EndpointId, RecordTransport};

/// Hard ceiling on one signed IPNS record fetched from a `/routing/v1`
/// endpoint. The IPNS spec caps a record at 10 KiB, and the endpoint set
/// includes at least one untrusted public endpoint — anything larger is a
/// hostile or broken endpoint whose bytes are never adoptable (#949).
pub const MAX_RECORD_BYTES: usize = 10 * 1024;

/// The outcome of a parallel PUT across the endpoint set.
pub struct Fanout {
    /// Endpoints that acknowledged the PUT.
    pub acked: Vec<EndpointId>,
    /// Endpoints that failed or had not answered when the first ack returned —
    /// the set a background retry re-PUTs (blueprint: "remaining PUTs retry in
    /// the background").
    pub not_acked: Vec<EndpointId>,
}

impl Fanout {
    /// Whether any endpoint acknowledged: the publish success condition
    /// (blueprint: "success = any ack").
    pub fn any_acked(&self) -> bool {
        !self.acked.is_empty()
    }
}

/// PUT `bytes` for `key` to every endpoint concurrently, returning as soon as
/// one endpoint acknowledges — the remaining endpoints (failed or still
/// in-flight) come back in [`Fanout::not_acked`] for a background retry. When
/// every endpoint settles with no ack, `acked` is empty and the caller fails
/// closed.
pub async fn fanout_put<T: RecordTransport>(transport: &T, key: &str, bytes: &[u8]) -> Fanout {
    let endpoints = transport.endpoints();
    let mut futs: Vec<_> = endpoints
        .iter()
        .map(|endpoint| Box::pin(transport.put_record(endpoint, key, bytes)))
        .collect();
    // Per-endpoint settle state: `Some(true)` acked, `Some(false)` failed,
    // `None` still pending.
    let mut status: Vec<Option<bool>> = vec![None; futs.len()];

    poll_fn(|cx| {
        let mut all_settled = true;
        for (index, fut) in futs.iter_mut().enumerate() {
            if status[index].is_some() {
                continue;
            }
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => status[index] = Some(true),
                Poll::Ready(Err(_)) => status[index] = Some(false),
                Poll::Pending => all_settled = false,
            }
        }
        // Return the instant one endpoint acks, or once every endpoint settled.
        if status.contains(&Some(true)) || all_settled {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    })
    .await;

    let mut acked = Vec::new();
    let mut not_acked = Vec::new();
    for (index, endpoint) in endpoints.iter().enumerate() {
        if status[index] == Some(true) {
            acked.push(endpoint.clone());
        } else {
            not_acked.push(endpoint.clone());
        }
    }
    Fanout { acked, not_acked }
}

/// Fan-out GET across the endpoint set and core-verify each returned record
/// against `name`, returning the freshest `(VerifiedRecord, record_bytes)` or
/// `None` when no endpoint serves a verifiable record. A malformed or
/// signature-invalid copy at one endpoint is ignored (an accelerator can serve
/// stale garbage); a per-endpoint transport error is tolerated as availability
/// staleness — only genuine host failure is surfaced.
///
/// This is the record-plane verify step (core's Ed25519-from-the-name chain);
/// the full adoption gate runs downstream on the chosen bytes. The
/// [`VerifiedRecord`] rides out so no caller re-verifies the same signature.
pub async fn fanout_get_verify<T: RecordTransport>(
    transport: &T,
    name: &IpnsName,
) -> Option<(VerifiedRecord, Vec<u8>)> {
    let key = name.as_str();
    let mut best: Option<(VerifiedRecord, Vec<u8>)> = None;
    for endpoint in transport.endpoints() {
        let Ok(Some(bytes)) = transport.get_record(&endpoint, key, MAX_RECORD_BYTES).await else {
            continue;
        };
        // Release-active backstop: a transport that ignores its cap must not
        // talk the engine past it (mirrors the WASM bridge's `send_capped`).
        if bytes.len() > MAX_RECORD_BYTES {
            continue;
        }
        let Ok(record) = IpnsRecord::unmarshal(&bytes) else {
            continue;
        };
        let Ok(verified) = record.verify(name) else {
            continue;
        };
        if best
            .as_ref()
            .is_none_or(|(current, _)| verified.sequence > current.sequence)
        {
            best = Some((verified, bytes));
        }
    }
    best
}
