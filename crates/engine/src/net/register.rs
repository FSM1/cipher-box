//! Registration: the bounded path to `POST /registry/register`
//! (blueprint/api.md "Batch bounds", "Register-first, fail-closed").

use super::REGISTRY_BATCH_MAX;
use crate::api::{ApiClient, ApiError, NameRegistration};
use crate::seams::{CredentialStore, Http};

/// Batch-register `entries`. Idempotent server-side (blueprint/api.md), so a
/// replayed batch — a resumed name wave, or a chunk a failed pass already sent
/// — is a no-op, never an error.
///
/// Both of the registry's bounds are enforced here so no caller carries them:
/// an entry past the per-entry `contentCids` cap splits into several entries
/// under the same `ipnsName` (the head rides the first), and the batch itself
/// chunks to [`REGISTRY_BATCH_MAX`] entries and [`REGISTRY_BATCH_MAX`] content
/// CIDs in total, which holds each body under
/// [`REGISTRY_BODY_MAX_BYTES`](super::REGISTRY_BODY_MAX_BYTES). A failing chunk
/// leaves the earlier ones registered and returns `Err`.
pub async fn register<H, C>(
    api: &ApiClient<H, C>,
    entries: &[NameRegistration],
) -> Result<(), ApiError>
where
    H: Http,
    C: CredentialStore,
{
    let mut chunk: Vec<NameRegistration> = Vec::new();
    let mut chunk_cids = 0;
    for piece in entries.iter().flat_map(split_entry) {
        if chunk.len() == REGISTRY_BATCH_MAX
            || chunk_cids + piece.content_cids.len() > REGISTRY_BATCH_MAX
        {
            api.register(&chunk).await?;
            chunk.clear();
            chunk_cids = 0;
        }
        chunk_cids += piece.content_cids.len();
        chunk.push(piece);
    }
    if !chunk.is_empty() {
        api.register(&chunk).await?;
    }
    Ok(())
}

/// One entry as the per-entry cap admits it. The head rides the first piece;
/// the rest carry content only, which leaves the name row's stored head
/// untouched (blueprint/api.md "Batch bounds").
fn split_entry(entry: &NameRegistration) -> Vec<NameRegistration> {
    let mut chunks = entry.content_cids.chunks(REGISTRY_BATCH_MAX);
    let head = NameRegistration {
        ipns_name: entry.ipns_name.clone(),
        head_cid: entry.head_cid.clone(),
        content_cids: chunks.next().unwrap_or_default().to_vec(),
    };
    core::iter::once(head)
        .chain(chunks.map(|chunk| NameRegistration {
            ipns_name: entry.ipns_name.clone(),
            head_cid: None,
            content_cids: chunk.to_vec(),
        }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::REGISTRY_BODY_MAX_BYTES;
    use crate::seams::{HttpMethod, HttpResponse};
    use crate::testkit::block_on;
    use crate::testkit::fakes::{InMemoryCredentialStore, ScriptedHttp};

    fn client() -> (
        ScriptedHttp,
        ApiClient<ScriptedHttp, InMemoryCredentialStore>,
    ) {
        let http = ScriptedHttp::default();
        let client = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "http://api.test",
        );
        (http, client)
    }

    fn ack(http: &ScriptedHttp, calls: usize) {
        for _ in 0..calls {
            http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
            });
        }
    }

    /// The batch each request carried, in wire order.
    fn sent(http: &ScriptedHttp) -> Vec<Vec<serde_json::Value>> {
        http.requests()
            .iter()
            .map(|request| {
                let body = request.body.as_deref().expect("a register call has a body");
                serde_json::from_slice(body).expect("a register body is a JSON array")
            })
            .collect()
    }

    /// The `contentCids` of one wire entry.
    fn cids(entry: &serde_json::Value) -> Vec<String> {
        entry["contentCids"]
            .as_array()
            .expect("contentCids")
            .iter()
            .map(|cid| cid.as_str().expect("a CID string").to_owned())
            .collect()
    }

    /// `entries` as the one batch they should go out as.
    fn wire(entries: &[NameRegistration]) -> Vec<Vec<serde_json::Value>> {
        let batch = serde_json::to_value(entries).expect("entries serialize");
        vec![batch.as_array().expect("a batch is an array").clone()]
    }

    fn entry(name: &str, head: Option<&str>, cids: usize) -> NameRegistration {
        NameRegistration {
            ipns_name: name.to_owned(),
            head_cid: head.map(str::to_owned),
            content_cids: (0..cids).map(|i| format!("cid{i}")).collect(),
        }
    }

    #[test]
    fn an_empty_batch_is_a_no_op_with_no_request() {
        let (http, client) = client();
        block_on(register(&client, &[])).expect("empty register");
        assert!(http.requests().is_empty(), "no entries means no API call");
    }

    #[test]
    fn an_in_bounds_entry_goes_out_untouched_in_one_batch() {
        let (http, client) = client();
        ack(&http, 1);
        let entries = vec![entry("k51name", Some("bafyHead"), 3)];
        block_on(register(&client, &entries)).expect("register");

        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert!(requests[0].url.ends_with("/registry/register"));
        assert_eq!(sent(&http), wire(&entries));
    }

    #[test]
    fn an_entry_past_the_per_entry_cap_splits_under_one_name() {
        let (http, client) = client();
        ack(&http, 2);
        let over_cap = entry("k51name", Some("bafyHead"), REGISTRY_BATCH_MAX + 2);
        block_on(register(&client, core::slice::from_ref(&over_cap))).expect("register");

        let pieces: Vec<serde_json::Value> = sent(&http).into_iter().flatten().collect();
        let sizes: Vec<usize> = pieces.iter().map(|entry| cids(entry).len()).collect();
        assert_eq!(sizes, vec![REGISTRY_BATCH_MAX, 2], "split at the cap");
        assert!(
            pieces
                .iter()
                .all(|entry| entry["ipnsName"] == over_cap.ipns_name),
            "every piece registers under the one name"
        );
        let heads: Vec<Option<&str>> = pieces
            .iter()
            .map(|entry| entry["headCid"].as_str())
            .collect();
        assert_eq!(
            heads,
            vec![Some("bafyHead"), None],
            "the head rides the first piece; the rest leave the stored head alone"
        );
        let sent_cids: Vec<String> = pieces.iter().flat_map(cids).collect();
        assert_eq!(
            sent_cids, over_cap.content_cids,
            "every CID reaches the registry once, in order"
        );
    }

    #[test]
    fn an_entry_with_no_content_still_registers_its_name_and_head() {
        let (http, client) = client();
        ack(&http, 1);
        let bare = vec![entry("k51name", Some("bafyHead"), 0)];
        block_on(register(&client, &bare)).expect("register");
        assert_eq!(sent(&http), wire(&bare));
    }

    #[test]
    fn an_oversize_batch_splits_into_chunks_the_server_accepts() {
        let (http, client) = client();
        ack(&http, 2);
        let entries: Vec<NameRegistration> = (0..REGISTRY_BATCH_MAX + 1)
            .map(|i| entry(&format!("k51name{i}"), None, 1))
            .collect();
        block_on(register(&client, &entries)).expect("register");

        let batches = sent(&http);
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![REGISTRY_BATCH_MAX, 1],
            "the batch splits at the server's cap"
        );
        assert_eq!(
            vec![batches.into_iter().flatten().collect::<Vec<_>>()],
            wire(&entries),
            "every entry still reaches the registry once"
        );
    }

    #[test]
    fn one_request_carries_at_most_the_cap_in_content_cids() {
        let (http, client) = client();
        ack(&http, 8);
        let entries: Vec<NameRegistration> = (0..3)
            .map(|i| entry(&format!("k51name{i}"), Some("bafyHead"), 600))
            .collect();
        block_on(register(&client, &entries)).expect("register");

        let batches = sent(&http);
        for batch in &batches {
            let total: usize = batch.iter().map(|entry| cids(entry).len()).sum();
            assert!(
                total <= REGISTRY_BATCH_MAX,
                "a request carries {total} content CIDs, past the cap"
            );
        }
        let sent_cids: Vec<(String, String)> = batches
            .iter()
            .flatten()
            .flat_map(|entry| {
                let name = entry["ipnsName"].as_str().expect("a name").to_owned();
                cids(entry).into_iter().map(move |cid| (name.clone(), cid))
            })
            .collect();
        let expected: Vec<(String, String)> = entries
            .iter()
            .flat_map(|entry| {
                entry
                    .content_cids
                    .iter()
                    .map(|cid| (entry.ipns_name.clone(), cid.clone()))
            })
            .collect();
        assert_eq!(
            sent_cids, expected,
            "every CID reaches the registry once, in order"
        );
        for entry in &entries {
            let first = batches
                .iter()
                .flatten()
                .find(|piece| piece["ipnsName"] == entry.ipns_name)
                .expect("every name is sent");
            assert_eq!(
                first["headCid"].as_str(),
                Some("bafyHead"),
                "the head rides the first piece of its name"
            );
        }
    }

    #[test]
    fn every_request_fits_the_registry_body_limit_at_the_widest_tokens() {
        let (http, client) = client();
        ack(&http, 64);
        // The widest tokens the registry DTOs admit: a 128-character name and
        // 256-character CIDs.
        let wide = |prefix: &str, i: usize, len: usize| {
            let token = format!("{prefix}{i}");
            format!("{token}{}", "a".repeat(len - token.len()))
        };
        let mut entries: Vec<NameRegistration> = (0..REGISTRY_BATCH_MAX + 500)
            .map(|i| NameRegistration {
                ipns_name: wide("k51name", i, 128),
                head_cid: Some(wide("bafyhead", i, 256)),
                content_cids: vec![wide("bafyleaf", i, 256)],
            })
            .collect();
        entries.push(NameRegistration {
            ipns_name: wide("k51large", 0, 128),
            head_cid: Some(wide("bafyhead", 0, 256)),
            content_cids: (0..20 * REGISTRY_BATCH_MAX)
                .map(|i| wide("bafylarge", i, 256))
                .collect(),
        });
        block_on(register(&client, &entries)).expect("register");

        for request in http.requests() {
            let size = request.body.as_deref().expect("a register body").len();
            assert!(
                size <= REGISTRY_BODY_MAX_BYTES,
                "a request body of {size} bytes is past the registry limit"
            );
        }
    }
}
