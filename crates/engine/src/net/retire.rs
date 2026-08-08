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
use std::collections::BTreeSet;

use cipherbox_core::content::{
    CONTENT_CID_LEN, decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid,
};

use super::REGISTRY_BATCH_MAX;
use crate::api::{ApiClient, ApiError};
use crate::content::{ContentPlane, ContentProfile, Gateway, expand_retire_targets, read_block};
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
/// Kept short because an entry's key is the longest the staging space holds and
/// the desktop store spells one as a hex filename — twice its byte length,
/// inside Windows' whole-path budget.
///
/// [`orphan_staging_keys`]: crate::sync::orphan_staging_keys
pub const RETIRE_LEDGER_PREFIX: &[u8] = b"cbx/rl/";

/// The fixed head of one stored entry: the owed figure then the manifest total,
/// both big-endian `u64`, followed by the retained-target list as binary CIDs.
const ENTRY_HEAD_LEN: usize = 2 * size_of::<u64>();

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

    /// One entry's key. The target rides as its **binary** CID, a third shorter
    /// than the multibase spelling and the form the suffix decodes back from.
    fn key(owner_tag: &[u8], target: &str) -> SeamResult<Vec<u8>> {
        let cid = decode_content_cid_str(target)
            .map_err(|_| SeamError::new("retire-ledger target is not a content CID"))?;
        let mut key = Self::scope(owner_tag)?;
        key.extend_from_slice(&cid);
        Ok(key)
    }
}

impl<St: StagingStore> RetireLedger for StagingRetireLedger<'_, St> {
    async fn owe(&self, owner_tag: &[u8], entries: &[OwedRetire]) -> SeamResult<()> {
        for entry in entries {
            let key = Self::key(owner_tag, &entry.target)?;
            // An unreadable entry is repaired rather than left to sit
            // undrainable forever.
            let stored = match decode_entry(self.0.staged_bytes(&key).await?) {
                None => encode_entry(entry.owed_bytes, entry.manifest_bytes, &entry.retained)?,
                // A held entry whose protection already covers the incoming one
                // stands, so a replayed prune cannot move what the vault reports
                // as pending.
                Some((.., retained)) if entry.retained.iter().all(|cid| retained.contains(cid)) => {
                    continue;
                }
                Some((owed_bytes, manifest_bytes, retained)) => {
                    let mut union: BTreeSet<String> = retained.into_iter().collect();
                    union.extend(entry.retained.iter().cloned());
                    encode_entry(
                        // A union protects at least what either side did, so the
                        // smaller figure bounds what the merged entry frees.
                        owed_bytes.min(entry.owed_bytes),
                        // The manifest total is the root block's own property,
                        // not the prune's, so the held figure stands.
                        manifest_bytes,
                        &union.into_iter().collect::<Vec<_>>(),
                    )?
                }
            };
            self.0.put_staged_bytes(&key, &stored).await?;
        }
        Ok(())
    }

    async fn owed(&self, owner_tag: &[u8]) -> SeamResult<Vec<OwedRetire>> {
        let scope = Self::scope(owner_tag)?;
        let mut entries = Vec::new();
        for key in self.0.staged_keys().await? {
            let Some(cid) = key
                .strip_prefix(&scope[..])
                .filter(|cid| is_wellformed_content_cid(cid))
            else {
                continue;
            };
            let Some((owed_bytes, manifest_bytes, retained)) =
                decode_entry(self.0.staged_bytes(&key).await?)
            else {
                continue;
            };
            entries.push(OwedRetire {
                target: encode_content_cid_str(cid),
                owed_bytes,
                manifest_bytes,
                retained,
            });
        }
        // Store enumeration order is host-dependent, and a pass can stop early;
        // sorted, it at least stops at the same place on every host.
        entries.sort_by(|a, b| a.target.cmp(&b.target));
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

/// One entry as the staging store holds it. The target itself is the key, so it
/// is not written into the value.
fn encode_entry(owed_bytes: u64, manifest_bytes: u64, retained: &[String]) -> SeamResult<Vec<u8>> {
    let mut stored = Vec::with_capacity(ENTRY_HEAD_LEN + retained.len() * CONTENT_CID_LEN);
    stored.extend_from_slice(&owed_bytes.to_be_bytes());
    stored.extend_from_slice(&manifest_bytes.to_be_bytes());
    for cid in retained {
        stored.extend_from_slice(
            &decode_content_cid_str(cid).map_err(|_| {
                SeamError::new("retire-ledger retained target is not a content CID")
            })?,
        );
    }
    Ok(stored)
}

/// One entry's owed figure, manifest total, and retained targets — or `None` for
/// bytes this build did not write. A partial or over-long trailer reads as
/// unwritten rather than as a shorter retained list, which would retire a target
/// the prune excluded. The target itself comes from the key, never the value.
fn decode_entry(stored: Option<Vec<u8>>) -> Option<(u64, u64, Vec<String>)> {
    let stored = stored?;
    if (stored.len().checked_sub(ENTRY_HEAD_LEN)?) % CONTENT_CID_LEN != 0 {
        return None;
    }
    let (owed, rest) = stored.split_first_chunk::<{ size_of::<u64>() }>()?;
    let (manifest, rest) = rest.split_first_chunk::<{ size_of::<u64>() }>()?;
    let retained = rest
        .chunks_exact(CONTENT_CID_LEN)
        .map(|cid| is_wellformed_content_cid(cid).then(|| encode_content_cid_str(cid)))
        .collect::<Option<Vec<String>>>()?;
    Some((
        u64::from_be_bytes(*owed),
        u64::from_be_bytes(*manifest),
        retained,
    ))
}

/// Work the ledger once and report the pinned bytes still owed afterwards — the
/// vault's pending-reclaim figure. `None` when the ledger could not be read, so
/// a store hiccup reports nothing rather than reporting no debt.
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
    profile: &ContentProfile,
) -> Option<u64>
where
    L: RetireLedger,
    H: Http,
    C: CredentialStore,
{
    let owed = ledger.owed(owner_tag).await.ok()?;
    let mut still_owed = 0u64;
    let mut registry_up = true;
    for entry in owed {
        let outcome = if registry_up {
            retire_owed(&entry, ledger, owner_tag, api, gateway, http, profile).await
        } else {
            RetireOutcome::RegistryDown
        };
        match outcome {
            RetireOutcome::Retired => {}
            RetireOutcome::Deferred => {
                still_owed = still_owed.saturating_add(entry.owed_bytes);
            }
            RetireOutcome::RegistryDown => {
                registry_up = false;
                still_owed = still_owed.saturating_add(entry.owed_bytes);
            }
        }
    }
    Some(still_owed)
}

/// How one owed entry's pass ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetireOutcome {
    /// The entry is settled and owes nothing further.
    Retired,
    /// Nothing this entry can do this pass — a root no source served, a manifest
    /// that is not this version's, or a store that would not take the settle. It
    /// stays owed and the pass moves on.
    Deferred,
    /// The registry refused or could not be reached — not this entry's fault,
    /// and not the next one's either.
    RegistryDown,
}

/// Retire one owed version's block set, less every target the prune's retained
/// versions also name ([`OwedRetire::retained`]).
///
/// The entry settles **between** the leaf batches and the root's own final
/// batch. The root is the expansion key, so an entry still owed once its root is
/// gone could never be re-expanded and would owe forever; settling first trades
/// that for a bounded leak — one root block, on the narrow window where the
/// final batch never lands.
async fn retire_owed<L, H, C>(
    entry: &OwedRetire,
    ledger: &L,
    owner_tag: &[u8],
    api: &ApiClient<H, C>,
    gateway: &Gateway,
    http: &H,
    profile: &ContentProfile,
) -> RetireOutcome
where
    L: RetireLedger,
    H: Http,
    C: CredentialStore,
{
    let Ok(expected) = decode_content_cid_str(&entry.target) else {
        return RetireOutcome::Deferred;
    };
    let Ok(root_block) =
        read_block(gateway, http, &entry.target, &expected, ContentPlane::Root).await
    else {
        return RetireOutcome::Deferred;
    };
    let Ok(expansion) =
        expand_retire_targets(&entry.target, &root_block, profile, entry.manifest_bytes)
    else {
        return RetireOutcome::Deferred;
    };
    let named = BTreeSet::from_iter(expansion.cids());
    // Every retained target a prune journals comes out of this same
    // content-verified expansion, so one that is not in it is a bent store, not
    // a wider protection — and it would silently protect nothing at all.
    if !entry.retained.iter().all(|cid| named.contains(cid)) {
        return RetireOutcome::Deferred;
    }
    let retirable = expansion.minus_retained(&BTreeSet::from_iter(entry.retained.iter().cloned()));
    // The ceiling on what this entry may free ([`OwedRetire::owed_bytes`]): a
    // store whose retained list would free *more* than the prune promised is not
    // one to retire from.
    if retirable.pinned_bytes > entry.owed_bytes {
        return RetireOutcome::Deferred;
    }
    let targets = retirable.cids();
    let Some((root, leaves)) = targets.split_last() else {
        return RetireOutcome::Deferred;
    };
    if root != &entry.target {
        return RetireOutcome::Deferred;
    }
    if retire(api, leaves).await.is_err() {
        return RetireOutcome::RegistryDown;
    }
    if ledger
        .settle(owner_tag, core::slice::from_ref(&entry.target))
        .await
        .is_err()
    {
        return RetireOutcome::Deferred;
    }
    // Past the settle the debt is discharged, so a refused root batch is a leaked
    // pin row rather than a reason to re-own it.
    let _ = retire(api, core::slice::from_ref(root)).await;
    RetireOutcome::Retired
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
            OwedRetire::whole(version.content_cid, version.pinned_bytes),
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

    /// The retire calls the pass made, one entry per batch, in order.
    fn retire_batches(http: &ScriptedHttp) -> Vec<Vec<String>> {
        http.requests()
            .iter()
            .filter(|request| request.url.ends_with("/registry/retire"))
            .map(|request| {
                serde_json::from_slice::<Vec<String>>(
                    request.body.as_deref().expect("a retire call has a body"),
                )
                .expect("a retire body is a JSON array")
            })
            .collect()
    }

    /// Every target the pass handed the registry, batch order preserved.
    fn retired_targets(http: &ScriptedHttp) -> Vec<String> {
        retire_batches(http).into_iter().flatten().collect()
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
        let remaining = block_on(drain_owed_retires(
            &ledger,
            owner,
            &api,
            &gateway(),
            http,
            &ContentProfile::CI,
        ))
        .expect("the ledger reads");
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
            retire_batches(&http),
            vec![leaf_cids, vec![entry.target.clone()]],
            "every leaf goes first; the expansion key rides its own final batch"
        );
        assert!(owed.is_empty(), "the registry's answer settles the entry");
        assert_eq!(remaining, 0, "nothing is still owed");
    }

    /// The root is the expansion key, so an entry still owed once its root is
    /// gone could never be re-expanded. The settle therefore lands *before* the
    /// root batch: a refused root leaks one pin row, where the other order owes
    /// forever.
    #[test]
    fn the_entry_settles_before_its_root_goes_so_a_refused_root_cannot_strand_it() {
        let (entry, root_block, leaf_cids) = owed_version(&[8u8; 40]);
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        // The leaf batch is answered; the root's own batch is not.
        let http = ScriptedHttp::default();
        let leaves = leaf_cids.clone();
        let cid = entry.target.clone();
        for _ in 0..32 {
            let (cid, leaves, root_block) = (cid.clone(), leaves.clone(), root_block.clone());
            http.enqueue_derived(move |request| {
                if request.url.ends_with("/registry/retire") {
                    let sent: Vec<String> =
                        serde_json::from_slice(request.body.as_deref().unwrap_or_default())
                            .unwrap_or_default();
                    return Ok(retire_answer((sent == leaves).then_some(1)));
                }
                if requested_cid(&request.url) == cid {
                    return Ok(HttpResponse {
                        status: 200,
                        headers: Vec::new(),
                        body: root_block,
                    });
                }
                Err(SeamError::new("no such block"))
            });
        }
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            owed.is_empty(),
            "the debt is discharged once the leaves are gone"
        );
        assert_eq!(remaining, 0);
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

    /// Which versions a prune retained is a whole-plan property only the prune
    /// saw, so it rides the entry. A target it names must never reach the
    /// registry, and the vault must owe only what the rest frees.
    #[test]
    fn a_retained_target_is_never_named_by_the_retire_that_carries_it() {
        let (whole, root_block, leaf_cids) = owed_version(&[9u8; 100]);
        let expansion = expand_retire_targets(
            &whole.target,
            &root_block,
            &ContentProfile::CI,
            whole.manifest_bytes,
        )
        .expect("expands");
        let hostage = leaf_cids[0].clone();
        let entry = OwedRetire {
            target: whole.target.clone(),
            owed_bytes: expansion
                .minus_retained(&BTreeSet::from([hostage.clone()]))
                .pinned_bytes,
            manifest_bytes: whole.manifest_bytes,
            retained: vec![hostage.clone()],
        };
        assert!(
            entry.owed_bytes < entry.manifest_bytes,
            "an aliased expansion frees less than its manifest accounts for"
        );
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);

        assert_eq!(
            retired_targets(&http),
            leaf_cids[1..]
                .iter()
                .cloned()
                .chain([entry.target.clone()])
                .collect::<Vec<_>>(),
            "the retained target is skipped; everything else keeps its order"
        );
        assert!(owed.is_empty(), "the entry still settles");
        assert_eq!(remaining, 0);
    }

    /// The retained list is the only record of what an entry must not retire, so
    /// a trailer this build did not write reads as no entry at all rather than
    /// as a shorter list.
    #[test]
    fn a_stored_entry_this_build_did_not_write_reads_as_nothing() {
        let (whole, ..) = owed_version(&[1u8; 40]);
        let entry = OwedRetire {
            retained: vec![whole.target.clone()],
            ..whole
        };
        let stored =
            encode_entry(entry.owed_bytes, entry.manifest_bytes, &entry.retained).expect("encodes");
        assert_eq!(
            decode_entry(Some(stored.clone())),
            Some((entry.owed_bytes, entry.manifest_bytes, entry.retained)),
            "a round trip is the whole entry"
        );
        for bytes in [
            Vec::new(),
            vec![0u8; ENTRY_HEAD_LEN - 1],
            [&stored[..], &[7u8; CONTENT_CID_LEN - 1]].concat(),
            [&stored[..], &[7u8; CONTENT_CID_LEN]].concat(),
        ] {
            assert_eq!(decode_entry(Some(bytes)), None);
        }
    }

    /// One root `contentCid` can ride two nodes' histories, so a held entry that
    /// protects less than the incoming one must not stand: the second prune's
    /// retained set is the only record that its own survivors alias these bytes.
    #[test]
    fn an_entry_that_protects_less_than_the_incoming_one_widens() {
        let (whole, root_block, leaf_cids) = owed_version(&[2u8; 100]);
        let expansion = expand_retire_targets(
            &whole.target,
            &root_block,
            &ContentProfile::CI,
            whole.manifest_bytes,
        )
        .expect("expands");
        let hostage = leaf_cids[0].clone();
        let protecting = OwedRetire {
            owed_bytes: expansion
                .minus_retained(&BTreeSet::from([hostage.clone()]))
                .pinned_bytes,
            retained: vec![hostage.clone()],
            ..whole.clone()
        };
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &whole);
        owe(&store, OWNER, &protecting);
        assert_eq!(
            block_on(StagingRetireLedger::new(&store).owed(OWNER)).expect("owed"),
            vec![protecting.clone()],
            "the wider protection widens the entry it merges into"
        );

        owe(&store, OWNER, &whole);
        assert_eq!(
            block_on(StagingRetireLedger::new(&store).owed(OWNER)).expect("owed"),
            vec![protecting],
            "and a replay that protects nothing does not narrow it again"
        );
    }

    /// Two prunes of one root can protect **non-comparable** sets, and the
    /// merged entry must still drain.
    #[test]
    fn two_prunes_protecting_disjoint_targets_merge_and_the_merged_entry_drains() {
        let (whole, root_block, leaf_cids) = owed_version(&[2u8; 100]);
        let expansion = expand_retire_targets(
            &whole.target,
            &root_block,
            &ContentProfile::CI,
            whole.manifest_bytes,
        )
        .expect("expands");
        assert!(
            leaf_cids.len() > 2,
            "two hostages and something left to free"
        );
        let protecting = |hostage: &String| OwedRetire {
            owed_bytes: expansion
                .minus_retained(&BTreeSet::from([hostage.clone()]))
                .pinned_bytes,
            retained: vec![hostage.clone()],
            ..whole.clone()
        };
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &protecting(&leaf_cids[0]));
        owe(&store, OWNER, &protecting(&leaf_cids[1]));

        let held = block_on(StagingRetireLedger::new(&store).owed(OWNER)).expect("owed");
        assert_eq!(
            held.iter()
                .map(|entry| BTreeSet::from_iter(entry.retained.iter().cloned()))
                .collect::<Vec<_>>(),
            vec![BTreeSet::from([leaf_cids[0].clone(), leaf_cids[1].clone()])],
            "neither prune's protection is dropped"
        );

        let http = ledger_http(&whole, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert_eq!(
            retired_targets(&http),
            leaf_cids[2..]
                .iter()
                .cloned()
                .chain([whole.target])
                .collect::<Vec<_>>(),
            "both hostages are skipped, and the merged entry still drains"
        );
        assert!(owed.is_empty(), "a widened entry is not a stuck one");
        assert_eq!(remaining, 0);
    }

    /// A merged entry's figure is a ceiling rather than the exact total, and the
    /// slack is worth one protected target. A store that bent a retained CID
    /// would spend that slack and retire the target it displaced, so membership
    /// of the entry's own content-verified expansion is what catches it.
    #[test]
    fn a_retained_target_the_expansion_does_not_name_retires_nothing() {
        let (whole, root_block, leaf_cids) = owed_version(&[8u8; 100]);
        let expansion = expand_retire_targets(
            &whole.target,
            &root_block,
            &ContentProfile::CI,
            whole.manifest_bytes,
        )
        .expect("expands");
        let without = |hostage: &String| {
            expansion
                .minus_retained(&BTreeSet::from([hostage.clone()]))
                .pinned_bytes
        };
        assert_eq!(
            without(&leaf_cids[0]),
            without(&leaf_cids[1]),
            "two equal-weight hostages, so the bent set reproduces the ceiling exactly"
        );
        let stranger = owed_version(&[9u8; 40]).2[0].clone();
        assert!(!expansion.cids().contains(&stranger));

        // What a merge of two prunes protecting {leaf 0} and {leaf 1} stores,
        // with the first CID bent to a stranger: the byte ceiling alone cannot
        // tell the difference, so leaf 0 would go to the registry unprotected.
        let bent = OwedRetire {
            owed_bytes: without(&leaf_cids[0]),
            retained: vec![stranger, leaf_cids[1].clone()],
            ..whole
        };
        let store = InMemoryStagingStore::default();
        block_on(store.put_staged_bytes(
            &StagingRetireLedger::<InMemoryStagingStore>::key(OWNER, &bent.target).expect("key"),
            &encode_entry(bent.owed_bytes, bent.manifest_bytes, &bent.retained).expect("encodes"),
        ))
        .expect("the store takes it");

        let http = ledger_http(&bent, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            retired_targets(&http).is_empty(),
            "a retained target off the expansion retires nothing at all"
        );
        assert_eq!(owed, vec![bent.clone()], "and stays owed");
        assert_eq!(remaining, bent.owed_bytes);
    }

    /// The stored figure is the ceiling on what an entry may free, so a store
    /// that lost an entry's retained targets — leaving an expansion that frees
    /// more than the prune ever promised — is not one to retire from.
    #[test]
    fn an_entry_that_would_free_more_than_it_promised_retires_nothing() {
        let (whole, root_block, _) = owed_version(&[3u8; 100]);
        let understated = OwedRetire {
            owed_bytes: whole.owed_bytes - 1,
            ..whole
        };
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &understated);

        let http = ledger_http(&understated, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);
        assert!(
            retired_targets(&http).is_empty(),
            "an expansion the stored figure does not cover retires nothing"
        );
        assert_eq!(owed, vec![understated.clone()], "and stays owed");
        assert_eq!(remaining, understated.owed_bytes);
    }

    /// The ledger is not authenticated, so a store that lost or bent an entry
    /// must never let a leaf ride the final batch in the root's place.
    #[test]
    fn an_entry_whose_retained_set_names_its_own_root_retires_nothing() {
        let (whole, root_block, _) = owed_version(&[4u8; 100]);
        let expansion = expand_retire_targets(
            &whole.target,
            &root_block,
            &ContentProfile::CI,
            whole.manifest_bytes,
        )
        .expect("expands");
        let entry = OwedRetire {
            // Consistent with the bent retained set, so the byte gate passes and
            // the missing expansion key is the only thing left to catch it.
            owed_bytes: expansion
                .minus_retained(&BTreeSet::from([whole.target.clone()]))
                .pinned_bytes,
            retained: vec![whole.target.clone()],
            ..whole
        };
        let store = InMemoryStagingStore::default();
        owe(&store, OWNER, &entry);

        let http = ledger_http(&entry, Some(root_block), Some(1));
        let (remaining, owed) = drain(&store, OWNER, &http);

        assert!(
            retired_targets(&http).is_empty(),
            "an entry that cannot name its own expansion key retires nothing"
        );
        assert_eq!(owed, vec![entry.clone()], "and stays owed");
        assert_eq!(remaining, entry.owed_bytes);
    }

    #[test]
    fn root_never_auto_retires_pending_the_migration_window() {
        assert!(
            !root_retire_ready(),
            "the old root lingers until the migration-window constant lands"
        );
    }
}
