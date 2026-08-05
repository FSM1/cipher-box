//! Conformance kit: [`RecordTransport`] endpoint enumeration, byte fidelity,
//! and the size cap.

use crate::seams::RecordTransport;

/// A cap no test record approaches, for the calls that are not exercising it.
const GENEROUS_CAP: usize = 64 * 1024;

/// Runs the `RecordTransport` contract against an implementation.
///
/// The caller supplies the payload because real `/routing/v1` endpoints
/// validate what they store: against a live endpoint, pass a genuinely
/// signed record and its real routing key; the in-memory fake accepts any
/// bytes. `routing_key` must be unpublished when the kit starts.
///
/// # Panics
/// Panics on the first contract violation.
pub async fn check<T>(transport: &T, routing_key: &str, record: &[u8])
where
    T: RecordTransport,
{
    let endpoints = transport.endpoints();
    assert!(
        !endpoints.is_empty(),
        "the configured endpoint set must never be empty"
    );

    // An unpublished key resolves to nothing, everywhere — absence is
    // `None`, not an error.
    for endpoint in &endpoints {
        assert_eq!(
            transport
                .get_record(endpoint, routing_key, GENEROUS_CAP)
                .await
                .unwrap(),
            None,
            "an unpublished routing key must GET as None"
        );
    }

    // PUT to every endpoint (the engine's parallel fan-out shape), then
    // read the exact bytes back from each.
    for endpoint in &endpoints {
        transport
            .put_record(endpoint, routing_key, record)
            .await
            .unwrap();
    }
    // The cap is inclusive: a record of exactly `max_bytes` is admitted.
    for endpoint in &endpoints {
        assert_eq!(
            transport
                .get_record(endpoint, routing_key, record.len())
                .await
                .unwrap()
                .as_deref(),
            Some(record),
            "record bytes must round-trip verbatim — transports never rewrite records"
        );
    }

    // One byte under the record's size fails closed: an over-cap body is never
    // handed to the engine, whatever the endpoint declares.
    if let Some(cap) = record.len().checked_sub(1) {
        for endpoint in &endpoints {
            assert!(
                transport
                    .get_record(endpoint, routing_key, cap)
                    .await
                    .is_err(),
                "a record over `max_bytes` must fail closed, never be truncated or admitted"
            );
        }
    }
}
