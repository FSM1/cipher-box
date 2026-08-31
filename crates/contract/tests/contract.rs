//! The live contract suite — the engine's hand-written API client exercised
//! against a real NestJS API on the CI stack (blueprint/testing.md).
//!
//! Coverage mirrors api.md surface for surface, over the auth/token surface
//! that exists server-side today: challenge-signature login and account
//! identity, refresh rotation with reuse detection, test-login environment
//! gating + deterministic keypair + cross-consistency with identity login, the
//! production block on the test-profile auth-limit override,
//! SIWE secondary surface, the login-method list and its unlink, logout
//! revocation, the pin/name registry and quota, the mailbox lifecycle, and a raw
//! endpoint round-trip.
//!
//! Each test skips (loudly) when `CONTRACT_API_URL` is unset — there is no
//! stack to hit locally. The merge-blocking `contract-suite` CI job always
//! sets it (and boots the stack), so the assertions always run there.

use cipherbox_contract::{
    MemoryCredentialStore, ReqwestHttp, api_url, gateway_url, hex_to_bytes, hex_to_scalar,
    prod_api_url, random_identity_signer, test_login_secret,
};
use cipherbox_core::content::{CONTENT_CID_CODEC, compute_cid, encode_content_cid_str};
use cipherbox_core::seal::{
    ChildScopeRef, GrantSetCommitment, Permission, PreservedFields, ReadBody, sign_grant_set,
};
use cipherbox_core::suite::ecdsa::{EcdsaSigner, EcdsaVerifier};
use cipherbox_core::suite::ed25519::Ed25519Signer;
use cipherbox_core::suite::x25519::X25519Secret;
use cipherbox_engine::api::{
    ApiClient, ApiError, AuthMethodKind, ChallengeSigner, IdentityChallengeSigner,
    NameRegistration, REGISTRY_BATCH_REFUSED,
};
use cipherbox_engine::content::{ContentProfile, DAG_ROOT_CODEC, assemble};
use cipherbox_engine::grants::{
    GrantRecipient, GranteeScopePlan, OwnerGrantKeys, ParentScopePlan, ScopeRootPromoter,
    SharePointer, create_grant,
};
use cipherbox_engine::mailbox::poll_verified;
use cipherbox_engine::net::REGISTRY_BATCH_MAX;
use cipherbox_engine::rotation::{
    CascadeResealResolver, CascadeTarget, LaggingNode, NodeRef, PrevEpochSeed, ResealSeeds,
    ResealedScopeRoot, ResolveFailure, RotationPublishError, ScopeRootIdentity, ScopeRootPublisher,
    SweepPublisher, SweepResolveFailure, SweepResolver, SweptChild, SweptNode, SweptScope,
    WriteHistory,
};
use cipherbox_engine::seams::{
    CredentialStore, Http, HttpCredentials, HttpMethod, HttpRequest, HttpResponse, Mailbox,
};
use cipherbox_engine::testkit::SeededEntropy;

type Client = ApiClient<ReqwestHttp, MemoryCredentialStore>;

fn new_client(base: &str) -> Client {
    ApiClient::new(ReqwestHttp::new(), MemoryCredentialStore::default(), base)
}

fn client_with_store(base: &str) -> (Client, MemoryCredentialStore) {
    let store = MemoryCredentialStore::default();
    let client = ApiClient::new(ReqwestHttp::new(), store.clone(), base);
    (client, store)
}

async fn client_seeded_with(base: &str, refresh_token: &[u8]) -> Client {
    let store = MemoryCredentialStore::default();
    store
        .store_refresh_token(refresh_token)
        .await
        .expect("seed the store");
    ApiClient::new(ReqwestHttp::new(), store, base)
}

/// Unwrap an auth-surface call, naming the per-IP throttle explicitly on a 429.
/// One bucket is shared by every login-shaped route, so exhausting it fails
/// whichever test happens to log in next — which reads as an unrelated auth
/// failure unless the diagnostic says otherwise.
fn expect_auth<T>(what: &str, result: Result<T, ApiError>) -> T {
    match result {
        Ok(value) => value,
        Err(ApiError::Status { status: 429, .. }) => panic!(
            "{what}: the API rate-limited the suite (429) on the per-IP auth bucket. Raise \
             THROTTLE_AUTH_LIMIT on the API under test."
        ),
        Err(error) => panic!("{what}: {error}"),
    }
}

/// A fresh account: a new client logged in with a random identity key, which
/// implicitly creates the account (challenge-signature first login). Every
/// contract run mints a brand-new account, so fixed name/CID strings below are
/// always a fresh `(account, ...)` pair — no cross-run collision on the shared
/// CI database.
async fn fresh_account(base: &str) -> Client {
    fresh_account_with_signer(base).await.0
}

/// The same, keeping the identity key it created the account with — which the
/// unlink surface re-proves.
async fn fresh_account_with_signer(base: &str) -> (Client, IdentityChallengeSigner) {
    let client = new_client(base);
    let signer = random_identity_signer();
    expect_auth(
        "identity login creates the account",
        client.login_identity(&signer).await,
    );
    (client, signer)
}

macro_rules! require_stack {
    ($name:literal) => {
        match api_url() {
            Some(base) => base,
            None => {
                eprintln!(
                    "SKIP {}: set CONTRACT_API_URL to run the contract suite against a live stack",
                    $name
                );
                return;
            }
        }
    };
}

#[tokio::test]
async fn api_health_round_trips() {
    let base = require_stack!("api_health_round_trips");
    let http = ReqwestHttp::new();
    let response = http
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{base}/health"),
            headers: Vec::new(),
            body: None,
            credentials: HttpCredentials::Include,
            timeout_ms: Some(10_000),
        })
        .await
        .expect("health request");
    assert_eq!(response.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&response.body).expect("health json");
    assert_eq!(body["status"], "ok");
}

#[tokio::test]
async fn challenge_signature_login_creates_and_reuses_the_account() {
    let base = require_stack!("challenge_signature_login_creates_and_reuses_the_account");
    let signer = random_identity_signer();

    let first = new_client(&base);
    let outcome = expect_auth("identity login", first.login_identity(&signer).await);
    assert!(outcome.is_new_user, "a fresh random key creates an account");
    assert!(first.is_authenticated());

    // The same identity key is the same account on a second, independent client.
    let second = new_client(&base);
    let outcome = expect_auth(
        "second identity login",
        second.login_identity(&signer).await,
    );
    assert!(!outcome.is_new_user, "same identity key is one account");
}

#[tokio::test]
async fn refresh_rotates_and_reuse_kills_the_family() {
    let base = require_stack!("refresh_rotates_and_reuse_kills_the_family");
    let (client, store) = client_with_store(&base);
    expect_auth(
        "login",
        client.login_identity(&random_identity_signer()).await,
    );

    let original = store
        .load_refresh_token()
        .await
        .expect("load")
        .expect("a token after login");
    client.refresh().await.expect("refresh");
    let rotated = store
        .load_refresh_token()
        .await
        .expect("load")
        .expect("a token after refresh");
    assert_ne!(original, rotated, "refresh rotates the token");

    // Replaying the already-used original triggers reuse detection: the whole
    // family is revoked, so even the rotated token now fails.
    let replay = client_seeded_with(&base, &original).await;
    assert!(
        matches!(replay.refresh().await, Err(ApiError::Unauthorized)),
        "a reused refresh token is rejected"
    );
    assert!(
        matches!(client.refresh().await, Err(ApiError::Unauthorized)),
        "reuse detection revoked the whole family"
    );
}

#[tokio::test]
async fn test_login_gates_the_secret_and_derives_a_stable_keypair() {
    let base = require_stack!("test_login_gates_the_secret_and_derives_a_stable_keypair");
    let secret = test_login_secret();
    let handle = "contract-suite-user";

    // A wrong secret is rejected (the secret gate is live).
    let wrong = new_client(&base);
    assert!(
        matches!(
            wrong
                .test_login(handle, "definitely-the-wrong-secret")
                .await,
            Err(ApiError::Unauthorized)
        ),
        "a wrong test-login secret is rejected"
    );

    // The right secret returns a deterministic keypair.
    let client = new_client(&base);
    let first = expect_auth("test login", client.test_login(handle, &secret).await);
    assert_eq!(
        first.public_key.len(),
        66,
        "compressed secp256k1 public key"
    );
    assert!(client.is_authenticated());

    let again = expect_auth(
        "second test login",
        new_client(&base).test_login(handle, &secret).await,
    );
    assert_eq!(first.public_key, again.public_key, "same handle, same key");
    assert_eq!(&*first.private_key, &*again.private_key);
    assert!(!again.is_new_user, "the account already existed");

    // The returned private key really is this account's identity key: a
    // challenge-signature login with it lands on the same account.
    let scalar = hex_to_scalar(&first.private_key).expect("valid private key hex");
    let signer = IdentityChallengeSigner::from_scalar(&scalar).expect("valid scalar");
    let identity = expect_auth(
        "identity login with the test key",
        new_client(&base).login_identity(&signer).await,
    );
    assert!(
        !identity.is_new_user,
        "the test-login keypair is the same account as challenge-signature login"
    );
}

#[tokio::test]
async fn test_login_is_hard_blocked_in_production() {
    let Some(prod) = prod_api_url() else {
        eprintln!(
            "SKIP test_login_is_hard_blocked_in_production: set CONTRACT_API_PROD_URL to a \
             production-mode API instance"
        );
        return;
    };
    let client = new_client(&prod);
    assert!(
        matches!(
            client
                .test_login("contract-suite-user", &test_login_secret())
                .await,
            Err(ApiError::Forbidden)
        ),
        "production mode must refuse test-login regardless of the secret"
    );
}

/// The catalog's per-IP auth limit — what production gets whatever
/// `THROTTLE_AUTH_LIMIT` says (`apps/api/src/ops/throttling.ts`).
const PRODUCTION_AUTH_LIMIT: usize = 10;

/// The test-profile auth-limit override is hard-blocked in production:
/// the CI job sets `THROTTLE_AUTH_LIMIT` far above the catalog limit for BOTH
/// instances, so the production-mode one still throttling inside a catalog
/// window is the live evidence that no configuration widens a real rate limit.
/// Malformed bodies on purpose: the throttler runs ahead of validation, so the
/// bucket fills without touching the auth path.
#[tokio::test]
async fn production_ignores_the_test_profile_auth_limit_override() {
    let Some(prod) = prod_api_url() else {
        eprintln!(
            "SKIP production_ignores_the_test_profile_auth_limit_override: set \
             CONTRACT_API_PROD_URL to a production-mode API instance"
        );
        return;
    };
    let http = ReqwestHttp::new();
    let mut statuses = Vec::new();
    let mut advertised = None;
    for _ in 0..=PRODUCTION_AUTH_LIMIT {
        let response = http
            .send(HttpRequest {
                method: HttpMethod::Post,
                url: format!("{prod}/auth/challenge"),
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body: Some(b"{}".to_vec()),
                credentials: HttpCredentials::Include,
                timeout_ms: Some(10_000),
            })
            .await
            .expect("challenge request");
        if advertised.is_none() {
            advertised = response
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("x-ratelimit-limit"))
                .map(|(_, value)| value.clone());
        }
        statuses.push(response.status);
        if response.status == 429 {
            break;
        }
    }

    assert!(
        statuses.contains(&429),
        "production throttled none of {} auth requests, so it honored THROTTLE_AUTH_LIMIT: {statuses:?}",
        PRODUCTION_AUTH_LIMIT + 1
    );
    // Pins the exact boundary, which the 429 alone does not: a production limit
    // accidentally cut to 1 would still throttle. The throttler emits the header
    // only on a request it admits, so an already-drained bucket yields none.
    if let Some(limit) = advertised {
        assert_eq!(
            limit,
            PRODUCTION_AUTH_LIMIT.to_string(),
            "production advertised a per-IP auth limit other than the catalog's {PRODUCTION_AUTH_LIMIT}"
        );
    }
}

#[tokio::test]
async fn siwe_secondary_surface_is_reachable_and_gated() {
    let base = require_stack!("siwe_secondary_surface_is_reachable_and_gated");
    let client = new_client(&base);

    // The nonce endpoint issues a fresh nonce.
    let nonce = expect_auth("siwe nonce", client.siwe_challenge().await);
    assert!(
        (8..=128).contains(&nonce.nonce.len())
            && nonce.nonce.chars().all(|c| c.is_ascii_alphanumeric()),
        "the live API issues a nonce inside the EIP-4361 class the client enforces, got {:?}",
        nonce.nonce
    );

    // A well-formed-but-unlinked SIWE login is refused (the wallet is not
    // linked to any account). The signature is shaped to pass DTO validation
    // (65-byte 0x-hex) so the request reaches the SIWE service.
    let message = format!(
        "localhost:5173 wants you to sign in with your Ethereum account:\n\
         0x0000000000000000000000000000000000000000\n\nNonce: {}\n",
        nonce.nonce
    );
    let signature = format!("0x{}", "ab".repeat(65));
    let error = client
        .siwe_login(&message, &signature)
        .await
        .expect_err("an unlinked SIWE login must fail");
    assert!(
        matches!(error, ApiError::Unauthorized | ApiError::Status { .. }),
        "unlinked/invalid SIWE is refused, got {error:?}"
    );
}

/// A link message the live API's DTO and SIWE parser both accept.
fn link_message(nonce: &str) -> String {
    format!(
        "localhost:5173 wants you to sign in with your Ethereum account:\n\
         0x0000000000000000000000000000000000000000\n\n\
         Link wallet to CipherBox account\n\nNonce: {nonce}\n"
    )
}

/// The engine formats a wallet signature once, at the facade, and a mocked
/// transport will certify whatever it is handed — so the shape only becomes a
/// fact here, where the DTO's `HEX_ETH_SIGNATURE` answers 400 for anything else
/// before the SIWE service runs.
#[tokio::test]
async fn siwe_link_sends_a_body_the_login_dto_accepts() {
    let base = require_stack!("siwe_link_sends_a_body_the_login_dto_accepts");
    let (client, signer) = fresh_account_with_signer(&base).await;

    let nonce = expect_auth("link nonce", client.siwe_link_challenge().await);
    let message = link_message(&nonce.nonce);
    // The exact string `Command::SiweLink` builds from 65 signature bytes.
    let signature = format!("0x{}", "ab".repeat(65));

    let error = client
        .siwe_link(&message, &signature, &signer)
        .await
        .expect_err("the all-0xab signature cannot recover a wallet address");
    assert!(
        !matches!(error, ApiError::Status { status: 400, .. }),
        "the API refused the engine's own link body as malformed: {error:?}"
    );
    assert!(
        matches!(error, ApiError::Unauthorized),
        "an unverifiable wallet signature is a 401 from the SIWE service, got {error:?}"
    );
}

/// A bearer alone must not add a login method: the link route re-proves the
/// account identity key exactly as unlink does.
#[tokio::test]
async fn siwe_link_without_a_fresh_challenge_is_refused() {
    let base = require_stack!("siwe_link_without_a_fresh_challenge_is_refused");
    let (client, _signer) = fresh_account_with_signer(&base).await;

    let nonce = expect_auth("link nonce", client.siwe_link_challenge().await);
    let message = link_message(&nonce.nonce);
    let signature = format!("0x{}", "ab".repeat(65));

    let error = client
        .siwe_link(&message, &signature, &random_identity_signer())
        .await
        .expect_err("a challenge bound to another key must not link");
    assert!(
        matches!(error, ApiError::Unauthorized),
        "a challenge the account's own key did not answer is a 401, got {error:?}"
    );
    assert_eq!(
        client.auth_methods().await.expect("methods").len(),
        1,
        "the refused link added nothing"
    );
}

// --- login methods: list and unlink (blueprint/api.md) ---------------------

#[tokio::test]
async fn auth_methods_lists_only_the_callers_rows_in_display_form() {
    let base = require_stack!("auth_methods_lists_only_the_callers_rows_in_display_form");
    let mine = fresh_account(&base).await;
    let theirs = fresh_account(&base).await;

    let rows = mine.auth_methods().await.expect("the caller's methods");
    assert_eq!(
        rows.len(),
        1,
        "a fresh account carries exactly its identity row"
    );
    assert_eq!(rows[0].kind, AuthMethodKind::Identity);
    assert!(!rows[0].id.is_empty() && !rows[0].created_at.is_empty());
    if let Some(display) = &rows[0].identifier_display {
        assert!(
            display.len() < 64,
            "the row carries a display form, never the 32-byte identifier hash: {display:?}"
        );
    }

    let others = theirs
        .auth_methods()
        .await
        .expect("the other account's rows");
    assert!(
        others
            .iter()
            .all(|row| rows.iter().all(|mine| mine.id != row.id)),
        "the read is scoped to the caller's own rows"
    );
}

/// The account IS its identity key, and `identityLogin` re-inserts the row on
/// the next login — so removing it would revoke nothing. Every account carries
/// one, which is also why the last-remaining-method refusal has no reachable
/// case here.
#[tokio::test]
async fn unlinking_the_identity_method_is_refused() {
    let base = require_stack!("unlinking_the_identity_method_is_refused");
    let (client, signer) = fresh_account_with_signer(&base).await;
    let rows = client.auth_methods().await.expect("methods");
    assert_eq!(rows.len(), 1, "a fresh account has one method");
    assert_eq!(rows[0].kind, AuthMethodKind::Identity);

    let error = client
        .unlink_auth_method(&rows[0].id, &signer)
        .await
        .expect_err("the identity method cannot be unlinked");
    assert!(
        matches!(error, ApiError::Status { status: 409, .. }),
        "an unlink that would revoke nothing is a 409, got {error:?}"
    );
    assert_eq!(
        client.auth_methods().await.expect("methods").len(),
        1,
        "the refused unlink deleted nothing"
    );
}

/// The challenge is bound to the key that asked for it, so a signature from any
/// other key proves nothing about the account being stripped — and that check
/// runs ahead of the last-method count, which is why a one-method account still
/// answers 401 rather than 409.
#[tokio::test]
async fn unlink_without_a_fresh_challenge_is_refused() {
    let base = require_stack!("unlink_without_a_fresh_challenge_is_refused");
    let (client, _signer) = fresh_account_with_signer(&base).await;
    let rows = client.auth_methods().await.expect("methods");

    let error = client
        .unlink_auth_method(&rows[0].id, &random_identity_signer())
        .await
        .expect_err("a challenge bound to another key must not unlink");
    assert!(
        matches!(error, ApiError::Unauthorized),
        "a challenge the account's own key did not answer is a 401, got {error:?}"
    );
    assert_eq!(
        client.auth_methods().await.expect("methods").len(),
        rows.len(),
        "the refused unlink deleted nothing"
    );
}

#[tokio::test]
async fn logout_revokes_the_refresh_token_server_side() {
    let base = require_stack!("logout_revokes_the_refresh_token_server_side");
    let (client, store) = client_with_store(&base);
    expect_auth(
        "login",
        client.login_identity(&random_identity_signer()).await,
    );
    let token = store
        .load_refresh_token()
        .await
        .expect("load")
        .expect("a token after login");

    client.logout().await.expect("logout");
    assert!(!client.is_authenticated());
    assert!(
        store.load_refresh_token().await.expect("load").is_none(),
        "logout clears the local refresh token"
    );

    // The server hard-deleted every refresh token: the old one no longer works.
    let replay = client_seeded_with(&base, &token).await;
    assert!(
        matches!(replay.refresh().await, Err(ApiError::Unauthorized)),
        "logout revoked the refresh token server-side"
    );
}

// --- pin/name registry and quota (blueprint/api.md) -------------------------

/// Register-first, fail-closed (blueprint/api.md): the register call is the one
/// mandatory gate — content enters the inventory only through a valid
/// registration, and a malformed one is refused wholesale, never partially
/// accepted. (End-to-end "publishing an unregistered name is refused" is the
/// engine publish pipeline's ordering law; the API's half is that the gate
/// exists and fails closed.)
#[tokio::test]
async fn register_first_gate_accepts_valid_and_refuses_malformed() {
    let base = require_stack!("register_first_gate_accepts_valid_and_refuses_malformed");
    let client = fresh_account(&base).await;

    // A well-formed registration opens the gate.
    let valid = vec![NameRegistration {
        ipns_name: "k51contractRegisterFirst".into(),
        head_cid: Some("bafyContractHead".into()),
        content_cids: vec!["bafyContractC1".into(), "bafyContractC2".into()],
    }];
    client
        .register(&valid)
        .await
        .expect("valid register accepted");

    // A structurally invalid name is refused (the batch is rejected wholesale,
    // so no content rides in behind an unregisterable name).
    let malformed = vec![NameRegistration {
        ipns_name: "not a valid ipns name!!".into(),
        head_cid: None,
        content_cids: vec!["bafyContractC3".into()],
    }];
    let error = client
        .register(&malformed)
        .await
        .expect_err("a malformed registration must be refused");
    assert!(
        matches!(error, ApiError::Status { status: 400, .. }),
        "register-first is fail-closed: a malformed batch is a 400, got {error:?}"
    );
}

/// Batch register/retire idempotency (blueprint/api.md): every upsert is
/// idempotent, so a replayed batch — the shape a resumed name wave or a retried
/// write sends — changes nothing and never errors.
#[tokio::test]
async fn batch_register_and_retire_are_idempotent() {
    let base = require_stack!("batch_register_and_retire_are_idempotent");
    let client = fresh_account(&base).await;

    let batch = vec![NameRegistration {
        ipns_name: "k51contractIdem".into(),
        head_cid: Some("bafyContractIdemHead".into()),
        content_cids: vec!["bafyContractIdemC".into()],
    }];

    // Replaying the same register batch is accepted both times.
    client.register(&batch).await.expect("first register");
    client.register(&batch).await.expect("replayed register");

    // Register carries no byte sizes (those come from the hosted upload path),
    // so a register-only account still reports zero used bytes — a durable,
    // idempotent invariant regardless of replay count.
    let quota = client.quota().await.expect("quota");
    assert_eq!(
        quota.used_bytes, 0,
        "register records membership, not bytes"
    );

    // Retiring the same targets twice is accepted both times (the second is a
    // no-op removal).
    // The retire ledger's done-signal is the registry's own answer, so the
    // client reads the counts back: the first call reports the rows it deleted,
    // the replay reports nothing left — positive evidence that makes a lost
    // response harmless.
    let targets = vec!["k51contractIdem".to_owned(), "bafyContractIdemC".to_owned()];
    let first = client.retire(&targets).await.expect("first retire");
    assert_eq!(
        first.retired, 2,
        "the registry reports the rows it deleted, got {first:?}"
    );
    let replay = client
        .retire(&targets)
        .await
        .expect("replayed retire is a no-op");
    assert_eq!(replay.retired, 0, "a replay finds nothing left to delete");
}

/// Union liveness (blueprint/api.md): inventory rows are per account and the
/// server authorizes nothing across accounts, so two accounts independently
/// hold rows for the same shared CID and each retires its own permissionlessly
/// — the self-healing shared-scope path. (Physical unpin fires only at GLOBAL
/// refcount zero; that decision is exercised by the api-unit refcounting suite
/// via the PinStore seam, as it is not observable through the client surface.)
#[tokio::test]
async fn union_liveness_is_per_account_and_permissionless() {
    let base = require_stack!("union_liveness_is_per_account_and_permissionless");
    let alice = fresh_account(&base).await;
    let bob = fresh_account(&base).await;

    let shared = "bafyContractUnionShared".to_owned();
    alice
        .register(&[NameRegistration {
            ipns_name: "k51contractUnionAlice".into(),
            head_cid: None,
            content_cids: vec![shared.clone()],
        }])
        .await
        .expect("alice registers the shared CID under her account");
    bob.register(&[NameRegistration {
        ipns_name: "k51contractUnionBob".into(),
        head_cid: None,
        content_cids: vec![shared.clone()],
    }])
    .await
    .expect("bob co-registers the same CID under his own account");

    // Each account retires only its own row; neither call authorizes or touches
    // the other account's inventory, and both succeed.
    let first = alice
        .retire(&[shared.clone()])
        .await
        .expect("alice retires her row while bob still references the CID");
    assert_eq!(first.retired, 1, "alice deleted exactly her own row");
    let repeat = alice
        .retire(&[shared.clone()])
        .await
        .expect("alice retires a row she no longer holds");
    assert_eq!(
        repeat.retired, 0,
        "a zero count is not evidence the CID is unreferenced — bob still holds it, \
         which is why the retire ledger is owner-scoped rather than count-driven"
    );
    bob.retire(&[shared])
        .await
        .expect("bob retires the last row");
}

/// The engine's own content address for a sealed leaf — the `raw` codec core
/// fixes for content blocks.
fn leaf_cid(bytes: &[u8]) -> String {
    encode_content_cid_str(&compute_cid(CONTENT_CID_CODEC, bytes))
}

/// Fetch one block back from the stack's trustless gateway by CID — the read
/// path's view of what the ingress actually pinned.
async fn fetch_block(cid: &str) -> Vec<u8> {
    let gateway = gateway_url().expect(
        "CONTRACT_GATEWAY_URL must be set alongside CONTRACT_API_URL; the suite cannot prove a \
         pinned block is retrievable without the stack's gateway",
    );
    let response = ReqwestHttp::new()
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{gateway}/ipfs/{cid}?format=raw"),
            headers: vec![("Accept".to_owned(), "application/vnd.ipld.raw".to_owned())],
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: Some(30_000),
        })
        .await
        .expect("gateway request");
    assert_eq!(
        response.status, 200,
        "the gateway serves the pinned block at {cid}"
    );
    response.body
}

/// Hosted ingress pins under the **caller-computed** content address
/// (blueprint/api.md Ingress). The engine addresses every block as CIDv1
/// base32 over a BLAKE3-256 multihash — `raw` for sealed leaves, `dag-cbor`
/// for DAG roots and record heads — and a published record's value is
/// `/ipfs/<that CID>`. If the store pinned bytes under an address of its own
/// choosing, every record would point at a block the accelerator does not hold.
///
/// The proof is the gateway round-trip, not the echoed CID: the API answers
/// with the address it was handed, so only fetching `/ipfs/<declared>` back and
/// byte-comparing shows the block really landed there.
#[tokio::test]
async fn upload_pins_under_the_caller_computed_content_address() {
    let base = require_stack!("upload_pins_under_the_caller_computed_content_address");
    let client = fresh_account(&base).await;

    // A sealed content leaf: `raw` codec.
    let leaf = vec![42u8; 96];
    let declared_leaf = leaf_cid(&leaf);
    let pinned = client
        .upload(&declared_leaf, &leaf)
        .await
        .expect("a leaf uploads under its own address");
    assert_eq!(
        pinned.cid, declared_leaf,
        "the API answers about our address"
    );
    assert_eq!(
        fetch_block(&declared_leaf).await,
        leaf,
        "the gateway serves our exact bytes at the address we computed"
    );

    // A DAG root over that leaf: `dag-cbor` codec, real det-CBOR bytes — the
    // same shape a record head block takes on the metadata publish path.
    let dag = assemble(
        &[compute_cid(CONTENT_CID_CODEC, &leaf)],
        ContentProfile::CI.chunk_size() as u64,
        &ContentProfile::CI,
    )
    .expect("assemble a one-leaf root");
    assert_eq!(
        dag.content_cid[1], DAG_ROOT_CODEC,
        "the root carries the dag-cbor codec, so both content-plane codecs are exercised"
    );
    let declared_root = encode_content_cid_str(&dag.content_cid);
    let pinned_root = client
        .upload(&declared_root, &dag.root_block)
        .await
        .expect("a dag-cbor root uploads under its own address");
    assert_eq!(pinned_root.cid, declared_root);
    assert_eq!(
        fetch_block(&declared_root).await,
        dag.root_block,
        "a dag-cbor root is served at the caller's address, not a re-chunked one"
    );

    // Fail closed on a declared address the bytes do not hash to: a permanent
    // 400, and the refused upload leaves no quota charge behind.
    let used_before = client
        .quota()
        .await
        .expect("quota before the mismatch")
        .used_bytes;
    // A CID no row references yet, so the ledger's idempotent re-upload
    // short-circuit cannot stand in for a real pin.
    let unregistered = leaf_cid(&[7u8; 96]);
    let mismatch = client
        .upload(&unregistered, &[9u8; 96])
        .await
        .expect_err("bytes that do not address to the declared CID are refused");
    assert!(
        matches!(mismatch, ApiError::Status { status: 400, .. }),
        "a CID/bytes mismatch is a permanent 400, got {mismatch:?}"
    );
    assert_eq!(
        client
            .quota()
            .await
            .expect("quota after the mismatch")
            .used_bytes,
        used_before,
        "a refused upload is compensated, not charged"
    );

    // A malformed declaration never reaches the pin path.
    let malformed = client
        .upload("not-a-cid", &leaf)
        .await
        .expect_err("a non-canonical content CID is refused");
    assert!(
        matches!(malformed, ApiError::MalformedContentCid),
        "the client refuses a non-canonical CID before the wire, got {malformed:?}"
    );
}

/// Quota + hosted ingress (blueprint/api.md): hosted accounts are
/// authoritative (`advisory: false`) with a positive limit and gate uploads; a
/// BYO account's quota is advisory (`advisory: true`, quota always allows) and
/// its bytes bypass the API entirely — so hosted ingress is REFUSED for a BYO
/// account rather than pinned off an uncounted row. The contract-suite job sets
/// a tiny 1 KiB QUOTA_DEFAULT_BYTES, so a few hundred bytes straddle the
/// over-quota limit deterministically.
#[tokio::test]
async fn quota_is_hosted_authoritative_and_byo_advisory() {
    let base = require_stack!("quota_is_hosted_authoritative_and_byo_advisory");
    let client = fresh_account(&base).await;

    // A fresh account is hosted: quota is authoritative and carries a limit.
    let hosted = client.quota().await.expect("hosted quota");
    assert!(
        !hosted.advisory,
        "a hosted account's quota is authoritative"
    );
    assert!(
        hosted.limit_bytes > 0,
        "a hosted account has a positive limit"
    );

    // A sub-limit hosted upload is pinned to Kubo and counts against the quota.
    let under = vec![7u8; 512];
    let pinned = client
        .upload(&leaf_cid(&under), &under)
        .await
        .expect("hosted upload under quota is pinned");
    assert_eq!(pinned.size, 512, "size is the uploaded byte count");
    assert_eq!(
        client.quota().await.expect("quota after upload").used_bytes,
        512,
        "the upload is counted against quota"
    );

    // An upload crossing the 1 KiB limit is refused for a hosted account.
    let over = vec![9u8; 600];
    let error = client
        .upload(&leaf_cid(&over), &over)
        .await
        .expect_err("an over-quota upload is refused for a hosted account");
    assert!(
        matches!(error, ApiError::Status { status: 413, .. }),
        "over-quota is a 413, got {error:?}"
    );

    // Enabling BYO makes the account's quota advisory (quota always allows), but
    // hosted ingress is a hosted-only path: a BYO account's bytes belong on its
    // own provider, so the upload endpoint refuses it (409) instead of pinning
    // to hosted Kubo off an uncounted row.
    client.set_byo(true).await.expect("enable BYO");
    let byo = client.quota().await.expect("byo quota");
    assert!(byo.advisory, "a BYO account's quota is advisory");
    assert_eq!(
        byo.limit_bytes, hosted.limit_bytes,
        "the limit is unchanged"
    );
    let byo_bytes = vec![3u8; 4096];
    let refused = client
        .upload(&leaf_cid(&byo_bytes), &byo_bytes)
        .await
        .expect_err("a BYO account cannot ingress to hosted Kubo");
    assert!(
        matches!(refused, ApiError::Status { status: 409, .. }),
        "hosted ingress for a BYO account is a 409, got {refused:?}"
    );

    // Toggling BYO back restores the authoritative posture.
    client.set_byo(false).await.expect("disable BYO");
    let restored = client.quota().await.expect("restored quota");
    assert!(
        !restored.advisory,
        "clearing BYO restores authoritative quota"
    );
}

/// The content write plane's residual API surface, composed the way the drain
/// composes it: a version's blocks upload one at a time, root last, then one
/// registration names the file's `ipnsName` and every block CID under it, and
/// an abandoned version retires the same set.
///
/// It exercises the API contract the drain depends on — per-block ingress, batch
/// registration carrying a whole block set, quota accounting over the sum, and
/// retirement of both a name and its content — against a real API, Postgres, and
/// Kubo.
#[tokio::test]
async fn a_content_version_uploads_registers_and_retires_as_one_block_set() {
    let base = require_stack!("a_content_version_uploads_registers_and_retires_as_one_block_set");
    let client = fresh_account(&base).await;

    // Three leaves and a root, the shape a multi-chunk version stages. The
    // contract-suite quota is 1 KiB, so the whole version stays well under it.
    let leaves: Vec<Vec<u8>> = (0..3u8).map(|i| vec![i; 96]).collect();
    let root = vec![0xAAu8; 64];
    let total_bytes = (leaves.len() * 96 + root.len()) as u64;

    // File order, root last — the order that keeps the still-staged set a
    // suffix, so a resumed drain re-sends only what has not landed.
    let mut content_cids = Vec::new();
    for block in leaves.iter().chain(core::iter::once(&root)) {
        let declared = leaf_cid(block);
        let uploaded = client
            .upload(&declared, block)
            .await
            .unwrap_or_else(|e| panic!("a version block uploads: {e:?}"));
        assert_eq!(
            uploaded.size,
            block.len() as u64,
            "the ingress reports the byte count it counted"
        );
        assert_eq!(
            uploaded.cid, declared,
            "every block of the version pins under the address the drain computed"
        );
        content_cids.push(uploaded.cid);
    }
    assert_eq!(
        client.quota().await.expect("quota after upload").used_bytes,
        total_bytes,
        "every block of the version counts against the account"
    );

    // Register-first: one batch names the file's write-plane name, its head
    // block, and the whole content block set.
    let name = "k51contractContentVersion".to_owned();
    let registration = vec![NameRegistration {
        ipns_name: name.clone(),
        head_cid: Some("bafyContractVersionHead".into()),
        content_cids: content_cids.clone(),
    }];
    client
        .register(&registration)
        .await
        .expect("a version's whole block set registers in one batch");
    // A republish re-registers the same set (the sub-EOL renewal shape).
    client
        .register(&registration)
        .await
        .expect("re-registering the same set is idempotent");

    // Abandonment retires the name and the content it pinned together.
    let mut targets = vec![name];
    targets.extend(content_cids);
    client.retire(&targets).await.expect("retire the version");
    assert_eq!(
        client.quota().await.expect("quota after retire").used_bytes,
        0,
        "retiring the block set releases every counted byte"
    );
    client
        .retire(&targets)
        .await
        .expect("a replayed retire is a no-op");
}

/// An abandoned version never registers: its blocks uploaded, the publish then
/// failed, and the `upload` calls alone are what created the accountable pin
/// rows. Retirement therefore has to name **every** block — a root-only retire
/// leaves the leaves charged forever against an account that can no longer
/// reach them. Hosted bytes must come back to the pre-upload figure.
#[tokio::test]
async fn an_abandoned_versions_whole_block_set_retires_back_to_the_pre_upload_figure() {
    let base = require_stack!(
        "an_abandoned_versions_whole_block_set_retires_back_to_the_pre_upload_figure"
    );
    let client = fresh_account(&base).await;

    // Refused mid-set, the way a 413 halts a drain: the leaves before the halt
    // landed, the ones after never did, and the root never went up at all.
    let landed: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0xB0 | i; 96]).collect();
    let mut targets = vec!["bafyContractAbandonedRoot".to_owned()];
    for block in &landed {
        targets.push(
            client
                .upload(&leaf_cid(block), block)
                .await
                .unwrap_or_else(|e| panic!("a version block uploads: {e:?}"))
                .cid,
        );
    }
    targets.push("bafyContractAbandonedLeafNeverSent".to_owned());
    assert_eq!(
        client.quota().await.expect("quota after upload").used_bytes,
        (landed.len() * 96) as u64,
        "an upload with no registration behind it still charges the account"
    );

    client
        .retire(&targets)
        .await
        .expect("an abandoned version retires its whole block set");
    assert_eq!(
        client.quota().await.expect("quota after retire").used_bytes,
        0,
        "abandonment returns the account to its pre-upload figure"
    );
}

/// A record's head block goes up through the same charged ingress a content
/// block does, and every publish attempt authors its own under a fresh seal
/// nonce — so an op that retried left one charged, unreferenced head row per
/// attempt. Retiring only the last of them leaves the rest spending the quota
/// that refuses later uploads.
#[tokio::test]
async fn every_head_block_a_retrying_publish_orphaned_retires_back_to_the_pre_upload_figure() {
    let base = require_stack!(
        "every_head_block_a_retrying_publish_orphaned_retires_back_to_the_pre_upload_figure"
    );
    let client = fresh_account(&base).await;

    // Three attempts at one record: byte-different heads under distinct
    // addresses, each uploaded and then registered under the same name the way
    // register-first composes it.
    let name = "k51contractOrphanedHeads".to_owned();
    let attempts: Vec<Vec<u8>> = (0..3u8).map(|i| vec![0xC0 | i; 96]).collect();
    let mut heads = Vec::new();
    for block in &attempts {
        let declared = leaf_cid(block);
        let uploaded = client
            .upload(&declared, block)
            .await
            .unwrap_or_else(|e| panic!("a head block uploads: {e:?}"));
        assert_eq!(
            uploaded.cid, declared,
            "a head block pins under the address the drain computed"
        );
        client
            .register(&[NameRegistration {
                ipns_name: name.clone(),
                head_cid: Some(declared.clone()),
                content_cids: Vec::new(),
            }])
            .await
            .expect("register-first names the head the attempt authored");
        heads.push(declared);
    }
    assert_eq!(
        client.quota().await.expect("quota after upload").used_bytes,
        (attempts.len() * 96) as u64,
        "each attempt's head charges the account on its own"
    );

    // Retiring only the head the last attempt registered is what the leak looks
    // like: the earlier two stay charged.
    client
        .retire(&heads[2..])
        .await
        .expect("retire the last attempt's head");
    assert_eq!(
        client
            .quota()
            .await
            .expect("quota after a partial retire")
            .used_bytes,
        (2 * 96) as u64,
        "the heads the earlier attempts orphaned are still charged"
    );

    let mut targets = heads[..2].to_vec();
    targets.push(name);
    client
        .retire(&targets)
        .await
        .expect("retire every head the retries orphaned");
    assert_eq!(
        client.quota().await.expect("quota after retire").used_bytes,
        0,
        "retiring every orphaned head returns the account to its pre-upload figure"
    );
}

/// The retire batch is bounded fail-closed (blueprint/api.md, "Batch bounds"):
/// an oversize array is refused, never truncated or partially applied. That
/// refusal is what makes the engine's client-side chunking mandatory rather than
/// cosmetic, so the bound belongs under the live gate.
#[tokio::test]
async fn an_oversize_retire_batch_is_refused_fail_closed() {
    let base = require_stack!("an_oversize_retire_batch_is_refused_fail_closed");
    let client = fresh_account(&base).await;

    // One past the documented 1000-item cap.
    let targets: Vec<String> = (0..1001).map(|i| format!("bafyContractBound{i}")).collect();
    let error = client
        .retire(&targets)
        .await
        .expect_err("an oversize retire batch must be refused");
    assert!(
        matches!(error, ApiError::Status { status: 400, .. }),
        "the retire bound is fail-closed: a 400, got {error:?}"
    );
    // The cap itself is the boundary the engine chunks to, so it must pass.
    client
        .retire(&targets[..1000])
        .await
        .expect("a batch at the cap is accepted");
}

/// A register entry's `contentCids` is bounded fail-closed the same way
/// (blueprint/api.md "Batch bounds"): an oversize array is refused, never
/// truncated, and the refusal carries the `code` the engine's failure valve
/// dead-letters on. Register-first blocks the record PUT on this call, so a
/// version past the cap could never publish without the chunking.
#[tokio::test]
async fn an_oversize_register_entry_is_refused_fail_closed() {
    let base = require_stack!("an_oversize_register_entry_is_refused_fail_closed");
    let client = fresh_account(&base).await;

    let name = "k51contractRegisterBound".to_owned();
    let head = "bafyContractEntryHead".to_owned();
    let cids: Vec<String> = (0..REGISTRY_BATCH_MAX + 1)
        .map(|i| format!("bafyContractEntry{i}"))
        .collect();
    let over_cap = NameRegistration {
        ipns_name: name.clone(),
        head_cid: Some(head.clone()),
        content_cids: cids.clone(),
    };
    let error = client
        .register(std::slice::from_ref(&over_cap))
        .await
        .expect_err("an oversize register entry must be refused");
    assert!(
        matches!(
            &error,
            ApiError::Status {
                status: 400,
                code: Some(code),
                ..
            } if code == REGISTRY_BATCH_REFUSED
        ),
        "the per-entry contentCids bound is fail-closed and stamped: {error:?}"
    );

    // The shape the engine's chunker sends: the cap-sized entry carrying the
    // head, then a content-only entry for the remainder under the same name.
    client
        .register(&[
            NameRegistration {
                ipns_name: name.clone(),
                head_cid: Some(head),
                content_cids: cids[..REGISTRY_BATCH_MAX].to_vec(),
            },
            NameRegistration {
                ipns_name: name,
                head_cid: None,
                content_cids: cids[REGISTRY_BATCH_MAX..].to_vec(),
            },
        ])
        .await
        .expect("chunked entries at the cap are accepted");
}

// --- mailbox (blueprint/api.md, Mailbox) ------------------------------------

/// An account addressable as a mailbox recipient: the client plus its identity
/// publicKey. Minted through test-login, whose deterministic per-handle keypair
/// gives each role a stable recipient address.
async fn addressable_account(base: &str, handle: &str) -> (Client, String) {
    let client = new_client(base);
    let outcome = expect_auth(
        "test login",
        client.test_login(handle, &test_login_secret()).await,
    );
    (client, outcome.public_key)
}

/// The mailbox lifecycle (blueprint/api.md, Mailbox): post → poll → ack over
/// the real routes.
#[tokio::test]
async fn mailbox_post_poll_ack_round_trips() {
    let base = require_stack!("mailbox_post_poll_ack_round_trips");
    let (sender, _) = addressable_account(&base, "contract-mailbox-sender").await;
    let (recipient, recipient_key) = addressable_account(&base, "contract-mailbox-recipient").await;

    let blob = b"contract-suite-sealed-blob".to_vec();
    let posted = sender
        .mailbox_post(&recipient_key, &blob, "contract-mailbox-idem")
        .await
        .expect("post to a known recipient");

    let items = recipient.mailbox_poll().await.expect("poll");
    assert_eq!(items.len(), 1, "one pending item");
    assert_eq!(items[0].id, posted, "the polled id is the posted id");
    assert_eq!(items[0].blob, blob, "the sealed blob round-trips opaquely");
    assert!(!items[0].received_at.is_empty(), "receivedAt is populated");
    assert!(
        sender.mailbox_poll().await.expect("sender poll").is_empty(),
        "a post lands only in the recipient's mailbox"
    );

    let replay = sender
        .mailbox_post(&recipient_key, &blob, "contract-mailbox-idem")
        .await
        .expect("replayed post");
    assert_eq!(replay, posted, "a replay returns the original message id");
    assert_eq!(
        recipient
            .mailbox_poll()
            .await
            .expect("poll after replay")
            .len(),
        1,
        "the replay delivered no second copy"
    );

    recipient.mailbox_ack(&posted).await.expect("ack");
    assert!(
        recipient
            .mailbox_poll()
            .await
            .expect("poll after ack")
            .is_empty(),
        "ack removes the item"
    );
    recipient
        .mailbox_ack(&posted)
        .await
        .expect("acking a gone id is a no-op");
}

/// The mailbox's two fail-closed post bounds (blueprint/api.md, Mailbox): the
/// rate-limited existence oracle, and the 8 KiB sealed-blob cap.
#[tokio::test]
async fn mailbox_post_is_bounded_by_recipient_existence_and_blob_size() {
    let base = require_stack!("mailbox_post_is_bounded_by_recipient_existence_and_blob_size");
    let (sender, recipient_key) = addressable_account(&base, "contract-mailbox-bounds").await;

    // A well-formed publicKey that has never logged in, so no account backs it.
    let stranger = random_identity_signer().public_key_hex();
    let error = sender
        .mailbox_post(&stranger, b"blob", "contract-mailbox-unknown")
        .await
        .expect_err("an unknown recipient must be refused");
    assert!(
        matches!(error, ApiError::Status { status: 404, .. }),
        "an unknown recipient is a 404, got {error:?}"
    );

    // One byte over the 8 KiB bound, and far short of the DTO's base64 length
    // cap, so the refusal is the spec bound and not DTO validation.
    let error = sender
        .mailbox_post(
            &recipient_key,
            &vec![1u8; 8193],
            "contract-mailbox-oversize",
        )
        .await
        .expect_err("an oversized blob must be refused");
    assert!(
        matches!(error, ApiError::Status { status: 413, .. }),
        "an oversized sealed blob is a 413, got {error:?}"
    );
}

// --- grant delivery over the live mailbox (blueprint/engine.md) -------------

/// The grant's whole net arm, kept local: this leg asserts the *delivery* the
/// grant path emits, not IPNS. The convergence gate measures the granted node
/// and finds it already at the scope epoch, so it advances nothing.
struct LocalNet;

/// The parent scope's read epoch, shared by the scope root and the granted node
/// so the node measures as converged.
const LOCAL_NET_READ_EPOCH: u64 = 3;

impl SweepResolver for LocalNet {
    async fn resolve_scope(
        &self,
        _scope: &ChildScopeRef,
    ) -> Result<SweptScope, SweepResolveFailure> {
        Ok(SweptScope {
            current_read_epoch: LOCAL_NET_READ_EPOCH,
            children: Vec::new(),
            direct_child_scope_index: Vec::new(),
        })
    }

    async fn consult_pointer(
        &self,
        _scope_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, SweepResolveFailure> {
        Ok(None)
    }

    async fn resolve_child(
        &self,
        _scope: &ChildScopeRef,
        _child: &NodeRef,
    ) -> Result<SweptChild, SweepResolveFailure> {
        Ok(SweptChild::Interior(SweptNode {
            current_read_epoch: LOCAL_NET_READ_EPOCH,
            sequence: 1,
            read_body: ReadBody::Folder {
                created_at: 0,
                modified_at: 0,
                children: Vec::new(),
                unknown: PreservedFields::new(),
            },
            carried_unknown: PreservedFields::new(),
            carried_epoch_tag_unknown: PreservedFields::new(),
        }))
    }
}

impl SweepPublisher for LocalNet {
    async fn publish_node(
        &self,
        _scope: &ChildScopeRef,
        _node: &LaggingNode<'_>,
    ) -> Result<(), RotationPublishError> {
        Ok(())
    }

    async fn repair_child_scope_index(
        &self,
        _scope: &ChildScopeRef,
        _index: &[ChildScopeRef],
    ) -> Result<(), RotationPublishError> {
        Ok(())
    }
}

impl CascadeResealResolver for LocalNet {
    async fn resolve(&self, _scope: &ChildScopeRef) -> Result<CascadeTarget, ResolveFailure> {
        Err(ResolveFailure::Rejected)
    }
}

impl ScopeRootPublisher for LocalNet {
    async fn publish_scope_root(
        &self,
        _record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        Ok(())
    }
}

impl ScopeRootPromoter for LocalNet {
    async fn promote_scope_root(
        &self,
        _parent: &ChildScopeRef,
        _node: &NodeRef,
        _record: &ResealedScopeRoot,
    ) -> Result<(), RotationPublishError> {
        Ok(())
    }
}

/// A real read grant's share pointer reaches the live mailbox: the grant path's
/// own routing address and idempotency key must satisfy `PostMessageDto`.
#[tokio::test]
async fn a_read_grant_delivers_its_share_pointer_through_the_live_mailbox() {
    let base = require_stack!("a_read_grant_delivers_its_share_pointer_through_the_live_mailbox");
    const V: u64 = 1;

    let (owner_client, _) = addressable_account(&base, "contract-grant-owner").await;
    let (recipient_client, recipient_key_hex) =
        addressable_account(&base, "contract-grant-recipient").await;

    // The recipient's mailbox address is their account identity key, exactly as
    // the API stores it — normalized compressed SEC1.
    let recipient_identity =
        EcdsaVerifier::from_sec1(&hex_to_bytes(&recipient_key_hex).expect("account key is hex"))
            .expect("account publicKey is a compressed secp256k1 point");

    let owner_enc = X25519Secret::from_scalar([0x11; 32]);
    let owner_enc_pub = owner_enc.public();
    let owner_identity = EcdsaSigner::from_scalar(&[0x33; 32]).expect("valid scalar");
    let owner_pseudonym = Ed25519Signer::from_seed([0x22; 32]);
    let recipient_enc = X25519Secret::from_scalar([0x44; 32]);
    let recipient_enc_pub = recipient_enc.public();

    let parent_node_seed = [0x44u8; 32];
    let grantee_write_scope_seed = [0x55u8; 32];
    let grantee_pointer_read_key = [0x66u8; 32];
    let parent_override_seed = [0x0au8; 32];
    let parent_write_scope_seed = [0x0bu8; 32];
    let parent_pointer_read_key = [0x0cu8; 32];
    let parent_commitment = GrantSetCommitment {
        ipns_name: b"contract-parent-scope-root".to_vec(),
        owner_pseudonym_pk: owner_pseudonym.verifying_key().to_bytes(),
        entries: Vec::new(),
        unknown: PreservedFields::new(),
    };
    let parent_commitment_sig = sign_grant_set(&owner_identity, &parent_commitment)
        .expect("sign the parent commitment")
        .to_compact();

    let mut entropy = SeededEntropy::new(954);
    let net = LocalNet;

    create_grant(
        &mut entropy,
        &net,
        &net,
        &owner_client,
        &GranteeScopePlan {
            v: V,
            scope_id: [0x5c; 16],
            parent_node_seed: &parent_node_seed,
            owner_enc_pub: &owner_enc_pub,
            write_scope_seed: &grantee_write_scope_seed,
            write_cut: None,
            pointer_read_key: &grantee_pointer_read_key,
            subtree_child_index: &[],
        },
        &GrantRecipient {
            identity_pk: recipient_identity,
            enc_pub: &recipient_enc_pub,
            display_name: "Shared Folder".to_string(),
        },
        &OwnerGrantKeys {
            enc_secret: &owner_enc,
            identity_signer: &owner_identity,
            pseudonym_signer: &owner_pseudonym,
        },
        &ParentScopePlan {
            identity: ScopeRootIdentity {
                v: V,
                scope_id: [0x0e; 16],
                ipns_name: b"contract-parent-scope-root",
                owner_enc_pub: &owner_enc_pub,
                owner_enc_secret: None,
                ascent: None,
                owes_ascent_link: false,
                pseudonym_signer: &owner_pseudonym,
            },
            seeds: ResealSeeds {
                override_seed: &parent_override_seed,
                read_epoch: 3,
                prev: None::<PrevEpochSeed<'_>>,
                write_scope_seed: &parent_write_scope_seed,
                write_epoch: 2,
                write_history: WriteHistory::Carried(&[]),
                pointer_read_key: &parent_pointer_read_key,
            },
            commitment: &parent_commitment,
            commitment_sig: &parent_commitment_sig,
            grant_ledger: &[],
            current_child_index: &[],
            carried_history_links: &[],
        },
    )
    .await
    .expect("the live mailbox accepts the grant path's own address and idempotency key");

    // The pointer landed in the recipient's real inbox, opens under their
    // encryption subkey, and carries the owner's signature — so the address the
    // grant path chose is the one the API routes on.
    let items = poll_verified(&recipient_client, &recipient_enc, V)
        .await
        .expect("recipient polls its inbox");
    assert_eq!(items.len(), 1, "exactly one delivered share pointer");
    assert_eq!(
        items[0].sender_identity,
        owner_identity.verifying_key(),
        "the pointer is sender-authenticated as the owner"
    );
    let pointer = SharePointer::decode(&items[0].payload).expect("decode the share pointer");
    assert_eq!(pointer.permission, Permission::Read);
    assert_eq!(
        pointer.sharer_identity_pk,
        owner_identity.verifying_key().to_sec1()
    );

    recipient_client
        .ack(&items[0].item_id)
        .await
        .expect("ack the delivered pointer");
}

// --- device approval (blueprint/api.md, Identity and auth) ------------------

/// A raw JSON POST against the live API, returning the status and body. The
/// device-approval surface is spoken by the host application over plain HTTP,
/// before the engine has a session to speak through, so the engine's API client
/// does not own it and the contract is proven the way a client speaks it.
///
/// A 429 is named here as `expect_auth` names it: every route below documents
/// one, so a throttled run would otherwise fail as the refusal under test.
async fn post_json(base: &str, path: &str, bearer: Option<&str>, body: serde_json::Value) -> u16 {
    post_json_response(base, path, bearer, body).await.status
}

/// The parsed body of a POST the caller expects to succeed.
async fn post_json_body(
    base: &str,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> serde_json::Value {
    let response = post_json_response(base, path, bearer, body).await;
    assert_eq!(response.status, 200, "{path}: expected a 200");
    serde_json::from_slice(&response.body).expect("json body")
}

async fn post_json_response(
    base: &str,
    path: &str,
    bearer: Option<&str>,
    body: serde_json::Value,
) -> HttpResponse {
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if let Some(token) = bearer {
        headers.push(("authorization".to_string(), format!("Bearer {token}")));
    }
    let response = ReqwestHttp::new()
        .send(HttpRequest {
            method: HttpMethod::Post,
            url: format!("{base}{path}"),
            headers,
            body: Some(serde_json::to_vec(&body).expect("serialize")),
            credentials: HttpCredentials::Include,
            timeout_ms: Some(10_000),
        })
        .await
        .expect("the API answers");
    assert_ne!(
        response.status, 429,
        "{path}: the API rate-limited the suite (429). Raise the throttle limits on the API \
         under test."
    );
    response
}

/// The access token of a fresh test-login session, read straight off the wire —
/// the engine's client keeps its own inside.
async fn test_login_access_token(base: &str, handle: &str) -> String {
    test_login_body(base, handle).await["accessToken"]
        .as_str()
        .expect("an access token")
        .to_string()
}

/// The whole token-response body of a fresh test-login session.
async fn test_login_body(base: &str, handle: &str) -> serde_json::Value {
    let response = ReqwestHttp::new()
        .send(HttpRequest {
            method: HttpMethod::Post,
            url: format!("{base}/auth/test-login"),
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Some(
                serde_json::to_vec(
                    &serde_json::json!({ "handle": handle, "secret": test_login_secret() }),
                )
                .expect("serialize"),
            ),
            credentials: HttpCredentials::Include,
            timeout_ms: Some(10_000),
        })
        .await
        .expect("the API answers");
    assert_ne!(
        response.status, 429,
        "test login: the API rate-limited the suite (429) on the per-IP auth bucket. Raise \
         THROTTLE_AUTH_LIMIT on the API under test."
    );
    assert_eq!(
        response.status, 200,
        "test login is available on the contract stack"
    );
    serde_json::from_slice(&response.body).expect("login json")
}

/// The status of a bare GET, optionally bearing `token` — how the gateway front
/// asks the API whether a read accelerator credential is still good.
async fn get_status(base: &str, path: &str, bearer: Option<&str>) -> u16 {
    let headers = match bearer {
        Some(token) => vec![("authorization".to_string(), format!("Bearer {token}"))],
        None => Vec::new(),
    };
    ReqwestHttp::new()
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{base}{path}"),
            headers,
            body: None,
            credentials: HttpCredentials::Omit,
            timeout_ms: Some(10_000),
        })
        .await
        .expect("the API answers")
        .status
}

/// The gateway leg presents a read-scoped pseudonym, not the session JWT: the
/// verify endpoint the accelerator's `forward_auth` front calls accepts the one
/// and refuses the other, and the pseudonym rotates with the access token.
#[tokio::test]
async fn the_accelerator_token_is_read_scoped_and_rotates_with_the_session() {
    let base = require_stack!("the_accelerator_token_is_read_scoped_and_rotates_with_the_session");
    let login = test_login_body(&base, "contract-accelerator-token").await;
    let accelerator_token = login["acceleratorToken"]
        .as_str()
        .expect("an accelerator token");
    let access_token = login["accessToken"].as_str().expect("an access token");

    assert_ne!(accelerator_token, access_token);
    assert_ne!(
        accelerator_token,
        login["refreshToken"].as_str().expect("a refresh token")
    );
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", Some(accelerator_token)).await,
        204,
        "the minted pseudonym opens the accelerator"
    );
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", Some(access_token)).await,
        401,
        "the session JWT is not a gateway credential"
    );
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", None).await,
        401,
        "the leg is gated, not open"
    );
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", Some(&"c".repeat(64))).await,
        401,
        "a well-formed token the API never minted is refused"
    );

    // A second session, never presented at the gateway: the API caches every
    // verified answer, so the superseded pseudonym of a session already checked
    // above would still be honoured for the length of that window.
    let rotating = test_login_body(&base, "contract-accelerator-rotation").await;
    let superseded = rotating["acceleratorToken"]
        .as_str()
        .expect("an accelerator token");
    let refreshed = post_json_body(
        &base,
        "/auth/refresh",
        None,
        serde_json::json!({ "refreshToken": rotating["refreshToken"] }),
    )
    .await;
    let rotated = refreshed["acceleratorToken"]
        .as_str()
        .expect("an accelerator token");

    assert_ne!(rotated, superseded, "refresh rotates the pseudonym");
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", Some(rotated)).await,
        204
    );
    assert_eq!(
        get_status(&base, "/auth/gateway/verify", Some(superseded)).await,
        401,
        "the superseded pseudonym stops opening the accelerator"
    );
}

/// A well-formed Ed25519 signature that is not the right one. It passes DTO
/// validation, so the request reaches the verification the assertion is about.
fn wrong_device_signature() -> String {
    "ab".repeat(64)
}

/// The device-approval surface refuses everything it cannot verify (ADR 0009 D4).
///
/// This is the live-wire half of that guarantee: the routes are mounted in a
/// really-booted API — which a suite that hand-lists controllers cannot show —
/// and each fails closed. The full rendezvous, from a valid registration to an
/// approval collected once and its row gone after, needs an identity token
/// minted from a verified provider credential that no headless suite can
/// produce, so it is proven against real Postgres in the API integration suite.
#[tokio::test]
async fn the_device_approval_surface_is_mounted_and_fails_closed() {
    let base = require_stack!("the_device_approval_surface_is_mounted_and_fails_closed");
    let device_key = "cd".repeat(32);
    let ephemeral_key = format!("02{}", "11".repeat(32));

    // A pre-reconstruction session is not mintable from an unverifiable token.
    assert_eq!(
        post_json(
            &base,
            "/device-approval/session",
            None,
            serde_json::json!({ "identityToken": "not.a.token" }),
        )
        .await,
        401,
        "an identity token this API did not mint opens no pre-reconstruction session"
    );

    // The device registry is authenticated.
    assert_eq!(
        post_json(
            &base,
            "/devices",
            None,
            serde_json::json!({
                "publicKey": device_key,
                "signature": wrong_device_signature(),
                "identityToken": "not.a.token",
            }),
        )
        .await,
        401,
        "the device registry refuses an anonymous caller"
    );

    let token = test_login_access_token(&base, "contract-device-approval").await;

    // A wrongly-signed registration is refused even under a real session: the
    // bearer proves the account, and nothing proves possession of the device key.
    assert_eq!(
        post_json(
            &base,
            "/devices",
            Some(&token),
            serde_json::json!({
                "publicKey": device_key,
                "signature": wrong_device_signature(),
                "identityToken": "not.a.token",
            }),
        )
        .await,
        401,
        "a registration whose signature does not verify is refused"
    );

    // And so is a wrongly-signed rendezvous request.
    assert_eq!(
        post_json(
            &base,
            "/device-approval/requests",
            Some(&token),
            serde_json::json!({
                "devicePublicKey": device_key,
                "ephemeralPublicKey": ephemeral_key,
                "signature": wrong_device_signature(),
            }),
        )
        .await,
        401,
        "a request whose signature does not verify opens no rendezvous"
    );

    // The account's registry is readable and empty — no refusal above wrote.
    let listed = ReqwestHttp::new()
        .send(HttpRequest {
            method: HttpMethod::Get,
            url: format!("{base}/devices"),
            headers: vec![("authorization".to_string(), format!("Bearer {token}"))],
            body: None,
            credentials: HttpCredentials::Include,
            timeout_ms: Some(10_000),
        })
        .await
        .expect("the API answers");
    assert_eq!(listed.status, 200);
    let body: serde_json::Value = serde_json::from_slice(&listed.body).expect("devices json");
    assert_eq!(
        body["devices"].as_array().map(Vec::len),
        Some(0),
        "no refused registration left a row behind"
    );
}
