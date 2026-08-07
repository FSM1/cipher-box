//! Retirement (blueprint/engine.md "Resolve/publish pipeline: Retirement",
//! #34 D4).
//!
//! Retire = remove my registry rows; the timing is engine policy. Interior old
//! names batch-retire at name-wave completion (immediate, [`retire`]); the old
//! scope-root name lingers serving the tombstone until the migration window
//! closes ([`root_retire_ready`], stubbed — see below).
//!
//! A pruned version's bytes are the one retirement that outlives the op that
//! ordered it ([`drain_owed_retires`]).

use core::cell::RefCell;

use cipherbox_core::content::decode_content_cid_str;

use super::REGISTRY_BATCH_MAX;
use crate::api::{ApiClient, ApiError};
use crate::content::{ContentPlane, Gateway, expand_retire_targets, read_block};
use crate::net::publish::PublishError;
use crate::net::record_publish::RecordPublishError;
use crate::seams::{
    CredentialStore, Http, OwedRetire, RetireLedger, SeamError, SeamResult, StagingStore,
};

/// Head blocks a publish left charged and unreachable, pending retirement.
///
/// Session-lived and shared by every publisher — the drain clears it at the end
/// of a pass, the settings publish at the point of failure — so a retire the
/// registry refused goes out again rather than being lost.
#[derive(Debug, Default)]
pub struct OrphanHeads(RefCell<Vec<String>>);

impl OrphanHeads {
    /// Note one head block as orphaned, capped at [`REGISTRY_BATCH_MAX`] so a
    /// session whose retires keep failing bounds its leak, not its memory.
    pub fn record(&self, cid: &str) {
        let mut pending = self.0.borrow_mut();
        if pending.len() < REGISTRY_BATCH_MAX && !pending.iter().any(|held| held == cid) {
            pending.push(cid.to_owned());
        }
    }

    /// Retire what is pending. A refused retire keeps the set rather than
    /// losing the only record of what to retire; a successful one clears the
    /// heads it actually sent, so a head recorded by an overlapping publisher
    /// mid-flight stays pending instead of being dropped unsent.
    pub async fn retire_pending<H, C>(&self, api: &ApiClient<H, C>)
    where
        H: Http,
        C: CredentialStore,
    {
        let pending = self.0.borrow().clone();
        if pending.is_empty() {
            return;
        }
        if retire(api, &pending).await.is_ok() {
            self.0.borrow_mut().retain(|cid| !pending.contains(cid));
        }
    }

    /// What is still pending, for tests and diagnostics.
    #[must_use]
    pub fn pending(&self) -> Vec<String> {
        self.0.borrow().clone()
    }
}

/// Whether a failed publish left its head block charged and unreachable: the
/// upload landed under its own pin row, no record naming it reached the
/// transport, and the retry re-authors under a fresh seal nonce
/// (blueprint/engine.md "Resolve/publish pipeline: Retirement").
#[must_use]
pub fn orphaned_head(error: &RecordPublishError) -> bool {
    match error {
        // A status answer is the server's own refusal, so it charged no row; a
        // dropped connection or an unreadable 2xx may have left one behind.
        RecordPublishError::Upload(error) => {
            matches!(error, ApiError::Transport(_) | ApiError::Decode(_))
        }
        RecordPublishError::HeadCidMismatch { .. } => true,
        RecordPublishError::Publish(error) => match error {
            // The head block is already uploaded and charged when publish
            // refuses, and no record naming it reached the transport.
            PublishError::Register(_)
            | PublishError::FloorRead(_)
            | PublishError::RecordTooLarge { .. } => true,
            // Nothing was ever addressed, so there is no CID to retire.
            PublishError::EmptyHeadCid => false,
            // No ack is not proof nothing stored: unpinning a head a live
            // record may still name is loss, where the row is only a leak.
            PublishError::AllEndpointsFailed => false,
        },
    }
}

/// Batch-retire registry rows for `targets` (`ipnsName`s or CIDs). Idempotent
/// server-side (blueprint/api.md), so a replayed batch — a resumed name wave, or
/// a chunk a failed pass already sent — is a no-op, never an error. This is the
/// interior-name path: it retires the moment the caller says a name is dead.
///
/// Chunked to [`REGISTRY_BATCH_MAX`] **in the order given**; a failing chunk
/// leaves the earlier ones retired and returns `Err`. Callers whose order is
/// load-bearing — the prune expansion, whose root must outlive its leaves — get
/// it from that.
pub async fn retire<H, C>(api: &ApiClient<H, C>, targets: &[String]) -> Result<(), ApiError>
where
    H: Http,
    C: CredentialStore,
{
    for chunk in targets.chunks(REGISTRY_BATCH_MAX) {
        api.retire(chunk).await?;
    }
    Ok(())
}

/// The staging-key prefix the [`StagingRetireLedger`] journals under.
///
/// The ledger rides the staging store's opaque key space rather than its op
/// queue: the queue is FIFO, cancellable, and swept of what it cannot decode at
/// cold start, and an owed retirement is none of those things.
/// [`orphan_staging_keys`] treats the whole prefix as referenced, every owner's
/// entries included.
///
/// [`orphan_staging_keys`]: crate::sync::orphan_staging_keys
pub const RETIRE_LEDGER_PREFIX: &[u8] = b"cipherbox/retire-ledger/";

/// The owed bytes as one ledger entry stores them.
const OWED_BYTES_LEN: usize = 8;

/// The [`RetireLedger`] every host gets for free, over the durable staging store
/// it already implements.
///
/// One key per entry, so `settle` is a single removal and a concurrent `owe` of
/// another target cannot lose it — there is no whole-set record to rewrite.
pub struct StagingRetireLedger<'a, St>(&'a St);

impl<'a, St: StagingStore> StagingRetireLedger<'a, St> {
    /// Wraps a staging store as the retire ledger.
    pub fn new(staging: &'a St) -> Self {
        Self(staging)
    }

    /// The key prefix every entry of one owner shares. The tag length is written
    /// in, so a shorter tag can never alias a longer one's entries.
    fn scope(owner_tag: &[u8]) -> SeamResult<Vec<u8>> {
        let len = u8::try_from(owner_tag.len())
            .map_err(|_| SeamError::new("retire-ledger owner tag is over 255 bytes"))?;
        let mut key = RETIRE_LEDGER_PREFIX.to_vec();
        key.push(len);
        key.extend_from_slice(owner_tag);
        Ok(key)
    }

    fn key(owner_tag: &[u8], target: &str) -> SeamResult<Vec<u8>> {
        let mut key = Self::scope(owner_tag)?;
        key.extend_from_slice(target.as_bytes());
        Ok(key)
    }
}

impl<St: StagingStore> RetireLedger for StagingRetireLedger<'_, St> {
    async fn owe(&self, owner_tag: &[u8], entries: &[OwedRetire]) -> SeamResult<()> {
        for entry in entries {
            let key = Self::key(owner_tag, &entry.target)?;
            // Held targets keep their stored figure: a replayed prune must not
            // double what the vault reports as pending.
            if self.0.staged_bytes(&key).await?.is_none() {
                self.0
                    .put_staged_bytes(&key, &entry.owed_bytes.to_be_bytes())
                    .await?;
            }
        }
        Ok(())
    }

    async fn owed(&self, owner_tag: &[u8]) -> SeamResult<Vec<OwedRetire>> {
        let scope = Self::scope(owner_tag)?;
        let mut entries = Vec::new();
        for key in self.0.staged_keys().await? {
            let Some(target) = key.strip_prefix(&scope[..]) else {
                continue;
            };
            // Bytes this build cannot read stay journaled: the entry is the only
            // record that the retirement is owed, so it is never discarded on
            // unreadable bookkeeping.
            let (Ok(target), Some(owed)) = (
                core::str::from_utf8(target),
                self.0.staged_bytes(&key).await?,
            ) else {
                continue;
            };
            let Ok(owed_bytes) = <[u8; OWED_BYTES_LEN]>::try_from(&owed[..]) else {
                continue;
            };
            entries.push(OwedRetire {
                target: target.to_owned(),
                owed_bytes: u64::from_be_bytes(owed_bytes),
            });
        }
        Ok(entries)
    }

    async fn settle(&self, owner_tag: &[u8], targets: &[String]) -> SeamResult<()> {
        for target in targets {
            self.0
                .remove_staged_bytes(&Self::key(owner_tag, target)?)
                .await?;
        }
        Ok(())
    }
}

/// Work the ledger once and report the pinned bytes still owed afterwards — the
/// vault's pending-reclaim figure.
///
/// Each entry is expanded from its own root block, fetched keyless (plaintext
/// det-CBOR), and retired in [`expand_retire_targets`] order.
///
/// An entry clears on the registry's own answer. Everything else — offline, an
/// expired token, a throttle, a root no source will serve — leaves the entry
/// owed and retries on a later pass; a registry that refused one batch also ends
/// the pass, since every remaining entry would spend a root fetch to fail the
/// same way. There is no attempt budget and no dead-letter class: every failure
/// is either self-clearing or ours, and the byte figure is the only record of
/// what was owed.
pub async fn drain_owed_retires<L, H, C>(
    ledger: &L,
    owner_tag: &[u8],
    api: &ApiClient<H, C>,
    gateway: &Gateway,
    http: &H,
) -> u64
where
    L: RetireLedger,
    H: Http,
    C: CredentialStore,
{
    let Ok(owed) = ledger.owed(owner_tag).await else {
        return 0;
    };
    let mut settled = Vec::new();
    let mut still_owed = 0u64;
    let mut registry_up = true;
    for entry in owed {
        let outcome = if registry_up {
            retire_owed(&entry, api, gateway, http).await
        } else {
            RetireOutcome::RegistryDown
        };
        match outcome {
            RetireOutcome::Retired => settled.push(entry.target),
            RetireOutcome::Unexpandable => {
                still_owed = still_owed.saturating_add(entry.owed_bytes);
            }
            RetireOutcome::RegistryDown => {
                registry_up = false;
                still_owed = still_owed.saturating_add(entry.owed_bytes);
            }
        }
    }
    if !settled.is_empty() {
        // A settle the store refused leaves the entries owed, and the next pass
        // replays their retire to a `retired: 0` — idempotent, never a
        // double-free.
        let _ = ledger.settle(owner_tag, &settled).await;
    }
    still_owed
}

/// How one owed entry's pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetireOutcome {
    /// The registry answered, so the entry clears.
    Retired,
    /// This entry alone could not be expanded: a malformed target, or a root no
    /// source served.
    Unexpandable,
    /// The registry refused or could not be reached — not this entry's fault,
    /// and not the next one's either.
    RegistryDown,
}

/// Retire one owed version's whole block set.
async fn retire_owed<H, C>(
    entry: &OwedRetire,
    api: &ApiClient<H, C>,
    gateway: &Gateway,
    http: &H,
) -> RetireOutcome
where
    H: Http,
    C: CredentialStore,
{
    let Ok(expected) = decode_content_cid_str(&entry.target) else {
        return RetireOutcome::Unexpandable;
    };
    let Ok(root_block) =
        read_block(gateway, http, &entry.target, &expected, ContentPlane::Root).await
    else {
        return RetireOutcome::Unexpandable;
    };
    let Ok(targets) = expand_retire_targets(&entry.target, &root_block) else {
        return RetireOutcome::Unexpandable;
    };
    match retire(api, &targets).await {
        Ok(()) => RetireOutcome::Retired,
        Err(_) => RetireOutcome::RegistryDown,
    }
}

/// Whether the old scope-root name may be retired yet. **Stubbed to `false`**:
/// the migration window that bounds how long the old root lingers serving the
/// tombstone is an open edge (blueprint/engine.md "Open edges: Migration-window
/// closure"; #38 fixed the channel architecture but not the window). Until it
/// lands the root never auto-retires, so a revokee or a lagging reader can
/// always chase the tombstone to the new root.
pub fn root_retire_ready() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::{HttpMethod, HttpResponse};
    use crate::testkit::fakes::{InMemoryCredentialStore, InMemoryStagingStore, ScriptedHttp};
    use crate::testkit::{block_on, doomed_version, gateway, requested_cid};

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

    /// The registry's own answer to a retire, as the ledger's done-signal reads
    /// it. `None` is a refusal.
    fn retire_answer(retired: Option<u64>) -> HttpResponse {
        HttpResponse {
            status: if retired.is_some() { 200 } else { 503 },
            headers: Vec::new(),
            body: format!(
                r#"{{"retired":{},"unpinned":0}}"#,
                retired.unwrap_or_default()
            )
            .into_bytes(),
        }
    }

    #[test]
    fn empty_retire_is_a_no_op_with_no_request() {
        let (http, client) = client();
        block_on(retire(&client, &[])).expect("empty retire");
        assert!(http.requests().is_empty(), "no targets means no API call");
    }

    #[test]
    fn retire_posts_the_batch_to_the_registry() {
        let (http, client) = client();
        http.enqueue_response(retire_answer(Some(1)));
        block_on(retire(&client, &["k51interior".to_owned()])).expect("retire");
        let requests = http.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, HttpMethod::Post);
        assert!(requests[0].url.ends_with("/registry/retire"));
    }

    #[test]
    fn an_oversize_batch_splits_into_chunks_the_server_accepts() {
        let (http, client) = client();
        let targets: Vec<String> = (0..REGISTRY_BATCH_MAX + 1)
            .map(|i| format!("cid{i}"))
            .collect();
        for _ in 0..2 {
            http.enqueue_response(retire_answer(Some(1)));
        }
        block_on(retire(&client, &targets)).expect("retire");

        let requests = http.requests();
        assert_eq!(requests.len(), 2, "the batch splits at the server's cap");
        let sent: Vec<String> = requests
            .iter()
            .flat_map(|request| {
                let body = request.body.as_deref().expect("a retire call has a body");
                serde_json::from_slice::<Vec<String>>(body).expect("a retire body is a JSON array")
            })
            .collect();
        assert_eq!(
            sent, targets,
            "every target still reaches the registry once"
        );
    }

    // -----------------------------------------------------------------------
    // The retire ledger.
    // -----------------------------------------------------------------------

    const OWNER: &[u8] = b"owner-tag";
    const OTHER_OWNER: &[u8] = b"another-owner-tag";

    /// The debt a prune journals for one sealed version.
    fn owed_version(plaintext: &[u8]) -> (OwedRetire, Vec<u8>, Vec<String>) {
        let (version, root_block, leaf_cids) = doomed_version(plaintext);
        (
            OwedRetire {
                target: version.content_cid,
                owed_bytes: version.pinned_bytes,
            },
            root_block,
            leaf_cids,
        )
    }

    /// A transport serving the doomed root off the gateway and answering the
    /// registry with `retired` — `None` being a refusal. An absent `root_block`
    /// is a root no source will serve.
    fn ledger_http(
        entry: &OwedRetire,
        root_block: Option<Vec<u8>>,
        retired: Option<u64>,
    ) -> ScriptedHttp {
        let http = ScriptedHttp::default();
        let cid = entry.target.clone();
        for _ in 0..32 {
            let cid = cid.clone();
            let root_block = root_block.clone();
            http.enqueue_derived(move |request| {
                if request.url.ends_with("/registry/retire") {
                    return Ok(retire_answer(retired));
                }
                match root_block.filter(|_| requested_cid(&request.url) == cid) {
                    Some(block) => Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: block,
                    }),
                    None => Err(SeamError::new("no such block")),
                }
            });
        }
        http
    }

    /// Every target the pass handed the registry, batch order preserved.
    fn retired_targets(http: &ScriptedHttp) -> Vec<String> {
        http.requests()
            .iter()
            .filter(|request| request.url.ends_with("/registry/retire"))
            .flat_map(|request| {
                serde_json::from_slice::<Vec<String>>(
                    request.body.as_deref().expect("a retire call has a body"),
                )
                .expect("a retire body is a JSON array")
            })
            .collect()
    }

    fn drain(
        store: &InMemoryStagingStore,
        owner: &[u8],
        http: &ScriptedHttp,
    ) -> (u64, Vec<OwedRetire>) {
        let ledger = StagingRetireLedger::new(store);
        let api = ApiClient::new(
            http.clone(),
            InMemoryCredentialStore::default(),
            "http://api.test",
        );
        let remaining = block_on(drain_owed_retires(&ledger, owner, &api, &gateway(), http));
        (remaining, block_on(ledger.owed(owner)).expect("owed"))
    }

    fn owe(store: &InMemoryStagingStore, owner: &[u8], entry: &OwedRetire) {
        block_on(StagingRetireLedger::new(store).owe(owner, core::slice::from_ref(entry)))
            .expect("owe");
    }

    #[test]
    fn a_drained_entry_retires_every_leaf_before_its_root_and_settles() {
        let plaintext: Vec<u8> = (0..100u8).collect();
        let (entry, root_block, leaf_cids) = owed_version(&plaintext);
        assert!(
            leaf_cids.len() > 1,
            "a multi-chunk version is the normal case"
        );
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);

        assert_eq!(
            retired_targets(&http),
            leaf_cids
                .into_iter()
                .chain([entry.target.clone()])
                .collect::<Vec<_>>(),
            "the expansion key retires after everything it names"
        );
        assert!(owed.is_empty(), "the registry's answer settles the entry");
        assert_eq!(remaining, 0, "nothing is still owed");
    }

    /// The done-signal is the registry's own answer, and a zero count is its
    /// positive form: the rows are gone, whether this call deleted them or a
    /// replay of a lost response did.
    #[test]
    fn a_retire_reporting_nothing_deleted_still_settles_the_entry() {
        let (entry, root_block, _) = owed_version(&[7u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(0));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(owed.is_empty());
        assert_eq!(remaining, 0);
    }

    #[test]
    fn a_refused_retire_keeps_the_debt_and_reports_it_as_pending() {
        let (entry, root_block, _) = owed_version(&[3u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), None);
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert_eq!(owed, vec![entry.clone()], "a refusal discards nothing");
        assert_eq!(
            remaining, entry.owed_bytes,
            "the vault still owes what the retire did not free"
        );
    }

    /// The root is the expansion key. Without it the leaves are unnameable, so
    /// the entry backs off rather than retiring a root whose leaves would then
    /// be charged forever.
    #[test]
    fn an_unfetchable_root_retires_nothing_and_stays_owed() {
        let (entry, ..) = owed_version(&[4u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, None, Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            retired_targets(&http).is_empty(),
            "a root that cannot be expanded retires nothing at all"
        );
        assert_eq!(owed, vec![entry.clone()]);
        assert_eq!(remaining, entry.owed_bytes);
    }

    /// Another account's token deletes no rows and answers the done-signal, so a
    /// pass under the wrong owner must never reach the debt.
    #[test]
    fn a_pass_under_another_owner_tag_neither_retires_nor_settles() {
        let (entry, root_block, _) = owed_version(&[5u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OTHER_OWNER, &http);
        assert!(retired_targets(&http).is_empty());
        assert_eq!(remaining, 0, "the other owner owes nothing");
        assert!(owed.is_empty());
        assert_eq!(
            block_on(StagingRetireLedger::new(&store).owed(OWNER)).expect("owed"),
            vec![entry],
            "the debt is untouched"
        );
    }

    /// A version past one batch is the normal case at the frozen framing, and
    /// resumability rests on the root surviving until every leaf is named.
    #[test]
    fn a_partially_retired_entry_stays_owed_and_replays_whole() {
        let (entry, root_block, leaf_cids) = owed_version(&[6u8; 100]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        // The first pass loses the registry.
        let failing = ledger_http(&entry, Some(root_block.clone()), None);
        let (remaining, owed) = drain(&store, OWNER, &failing);
        assert_eq!(owed, vec![entry.clone()]);
        assert_eq!(remaining, entry.owed_bytes);

        // The second re-expands from the still-pinned root and names the whole
        // set again — idempotent server-side, so a replay is a no-op.
        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert_eq!(
            retired_targets(&http),
            leaf_cids
                .into_iter()
                .chain([entry.target])
                .collect::<Vec<_>>()
        );
        assert!(owed.is_empty());
        assert_eq!(remaining, 0);
    }

    #[test]
    fn root_never_auto_retires_pending_the_migration_window() {
        assert!(
            !root_retire_ready(),
            "the old root lingers until the migration-window constant lands"
        );
    }
}
