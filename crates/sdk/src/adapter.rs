//! Real `NodeFetcher` adapter (`ApiNodeFetcher`) + journal high-water factory.
//!
//! `ApiNodeFetcher` composes `cipherbox_api_client::ipns::resolve_ipns_verified`
//! (the D-08 verified chokepoint) + `cipherbox_api_client::ipfs::fetch_content`
//! to implement `crate::listing::NodeFetcher` — making `list_folder`/
//! `list_shared_folder` callable from the FUSE daemon (P1b) without a raw
//! resolve.
//!
//! DUMB FETCHER (T-69-16-01 / landmine 6): `ApiNodeFetcher::fetch` performs NO
//! decode/unseal/gate. All gating stays in the `pub(crate)`
//! `resolve_published_node` (SC#6, `crates/sdk/src/listing.rs`); this adapter
//! returns the raw still-sealed envelope bytes + the verified sequence number
//! only — the untrusted bytes the gated resolve later decodes.
//!
//! `new_journal_high_water` (A3) is the factory returning a
//! `RotationHighWater<JsonSidecarFloorStore>` wired to the combined
//! generation+seq sidecar (D-06, a single `rotation-high-water.json`
//! adjacent to a journal dir); the FUSE daemon (P1b) supplies the concrete
//! path. This crate only homes the factory.
//!
//! No new Cargo dependency: `crates/sdk` already depends on
//! `cipherbox-api-client` (used by `registry.rs`).

use cipherbox_api_client::ipfs::fetch_content;
use cipherbox_api_client::ipns::{resolve_ipns_verified, VerifyError};
use cipherbox_api_client::ApiClient;

use crate::floor_store::JsonSidecarFloorStore;
use crate::listing::{FetchedRecord, ListingError, NodeFetcher};
use crate::rotation::RotationHighWater;

/// The real `NodeFetcher`: resolves `ipns_name` via the D-08 verified
/// chokepoint, then fetches its raw (still-sealed) `PublishedNode` envelope
/// bytes. Performs NO decode/unseal/gate — that all happens downstream in
/// `crate::listing::resolve_published_node` (the sole gating site, SC#6).
pub struct ApiNodeFetcher<'a> {
    pub api: &'a ApiClient,
}

impl NodeFetcher for ApiNodeFetcher<'_> {
    async fn fetch(&self, ipns_name: &str) -> Result<FetchedRecord, ListingError> {
        let verified = resolve_ipns_verified(self.api, ipns_name)
            .await
            .map_err(|e| map_verify_err(ipns_name, e))?;

        let bytes = fetch_content(self.api, &verified.cid).await.map_err(|e| {
            ListingError::FetchFailed {
                ipns_name: ipns_name.to_string(),
                message: e.to_string(),
            }
        })?;

        Ok(to_fetched(verified.sequence_number, bytes))
    }
}

/// Pure record-bind helper: assembles a `FetchedRecord` from a verified
/// sequence number and the raw (still-sealed) envelope bytes. No decode/
/// unseal happens here.
fn to_fetched(sequence_number: u64, bytes: Vec<u8>) -> FetchedRecord {
    FetchedRecord {
        sequence_number,
        bytes,
    }
}

/// Pure error-map helper: a `VerifyError` from the D-08 verified-resolve
/// chokepoint (either an API-level failure or an invalid/tampered signature)
/// maps to `ListingError::FetchFailed` — never a panic, never a silent empty
/// record.
fn map_verify_err(ipns_name: &str, e: VerifyError) -> ListingError {
    ListingError::FetchFailed {
        ipns_name: ipns_name.to_string(),
        message: e.to_string(),
    }
}

/// A3: factory constructing the `RotationHighWater<JsonSidecarFloorStore>`
/// wired to the combined generation+seq sidecar (D-06) adjacent to
/// `journal_dir` (`rotation-high-water.json`). The FUSE daemon (P1b, 69-09)
/// supplies the concrete journal-dir path; this crate only homes the
/// factory (Open Question A3).
pub fn new_journal_high_water(
    journal_dir: impl AsRef<std::path::Path>,
) -> RotationHighWater<JsonSidecarFloorStore> {
    RotationHighWater::new(
        JsonSidecarFloorStore::for_generation(&journal_dir),
        JsonSidecarFloorStore::for_seq(&journal_dir),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rotation::EnforceResolvedParams;
    use cipherbox_api_client::ApiError;

    // -----------------------------------------------------------------
    // Pure record-bind: to_fetched
    // -----------------------------------------------------------------

    #[test]
    fn to_fetched_binds_sequence_and_bytes_verbatim() {
        let record = to_fetched(42, vec![1, 2, 3, 4]);
        assert_eq!(record.sequence_number, 42);
        assert_eq!(record.bytes, vec![1, 2, 3, 4]);
    }

    // -----------------------------------------------------------------
    // Pure error-map: map_verify_err
    // -----------------------------------------------------------------

    #[test]
    fn map_verify_err_api_variant_maps_to_fetch_failed() {
        let err = map_verify_err(
            "ipns-name-1",
            VerifyError::Api(ApiError::IpnsNotFound("ipns-name-1".to_string())),
        );
        match err {
            ListingError::FetchFailed { ipns_name, message } => {
                assert_eq!(ipns_name, "ipns-name-1");
                assert!(message.contains("ipns-name-1"));
            }
            other => panic!("expected FetchFailed, got: {:?}", other),
        }
    }

    #[test]
    fn map_verify_err_invalid_variant_maps_to_fetch_failed() {
        let err = map_verify_err(
            "ipns-name-2",
            VerifyError::Invalid("signature verification failed".to_string()),
        );
        match err {
            ListingError::FetchFailed { ipns_name, message } => {
                assert_eq!(ipns_name, "ipns-name-2");
                assert!(message.contains("signature verification failed"));
            }
            other => panic!("expected FetchFailed, got: {:?}", other),
        }
    }

    // -----------------------------------------------------------------
    // new_journal_high_water: constructs over a temp dir, round-trips a
    // floor through enforce_resolved, and survives a fresh construction
    // over the same dir (mirrors floor_store.rs's restart test).
    // -----------------------------------------------------------------

    fn make_temp_dir() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("cipherbox-adapter-test-{}-{}", pid, seq));
        std::fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[tokio::test]
    async fn new_journal_high_water_round_trips_a_floor_through_enforce_resolved() {
        let dir = make_temp_dir();
        {
            let rhw = new_journal_high_water(&dir);
            rhw.enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 5,
                generation: 2,
                version_floor: 0,
            })
            .await
            .expect("forward resolve accepted");
        } // dropped -- simulates daemon restart

        let rhw = new_journal_high_water(&dir);
        assert_eq!(rhw.get_generation_floor("node-1").await, Some(2));
        assert_eq!(rhw.get_seq_floor("node-1").await, Some(5));

        // A regressed seq must be rejected against the persisted floor.
        let err = rhw
            .enforce_resolved(EnforceResolvedParams {
                node_id: "node-1".to_string(),
                seq: 3,
                generation: 2,
                version_floor: 0,
            })
            .await
            .expect_err("stale seq must be rejected after reconstruction");
        assert!(matches!(
            err,
            crate::rotation::RotationError::SequenceRegression { .. }
        ));
    }
}
