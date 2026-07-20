//! The live contract suite — the engine's hand-written API client exercised
//! against a real NestJS API on the CI stack (blueprint/testing.md).
//!
//! Coverage mirrors api.md surface for surface, over the auth/token surface
//! that exists server-side today (#624): challenge-signature login and account
//! identity, refresh rotation with reuse detection, test-login environment
//! gating + deterministic keypair + cross-consistency with identity login,
//! SIWE secondary surface, logout revocation, and a raw endpoint round-trip.
//!
//! Each test skips (loudly) when `CONTRACT_API_URL` is unset — there is no
//! stack to hit locally. The merge-blocking `contract-suite` CI job always
//! sets it (and boots the stack), so the assertions always run there.

use cipherbox_contract::{
    MemoryCredentialStore, ReqwestHttp, api_url, hex_to_scalar, prod_api_url,
    random_identity_signer, test_login_secret,
};
use cipherbox_engine::api::{ApiClient, ApiError, IdentityChallengeSigner, NameRegistration};
use cipherbox_engine::seams::{CredentialStore, Http, HttpMethod, HttpRequest};

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

/// A fresh account: a new client logged in with a random identity key, which
/// implicitly creates the account (challenge-signature first login). Every
/// contract run mints a brand-new account, so fixed name/CID strings below are
/// always a fresh `(account, ...)` pair — no cross-run collision on the shared
/// CI database.
async fn fresh_account(base: &str) -> Client {
    let client = new_client(base);
    client
        .login_identity(&random_identity_signer())
        .await
        .expect("identity login creates the account");
    client
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
    let outcome = first.login_identity(&signer).await.expect("identity login");
    assert!(outcome.is_new_user, "a fresh random key creates an account");
    assert!(first.is_authenticated());

    // The same identity key is the same account on a second, independent client.
    let second = new_client(&base);
    let outcome = second
        .login_identity(&signer)
        .await
        .expect("second identity login");
    assert!(!outcome.is_new_user, "same identity key is one account");
}

#[tokio::test]
async fn refresh_rotates_and_reuse_kills_the_family() {
    let base = require_stack!("refresh_rotates_and_reuse_kills_the_family");
    let (client, store) = client_with_store(&base);
    client
        .login_identity(&random_identity_signer())
        .await
        .expect("login");

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
    let first = client
        .test_login(handle, &secret)
        .await
        .expect("test login");
    assert_eq!(
        first.public_key.len(),
        66,
        "compressed secp256k1 public key"
    );
    assert!(client.is_authenticated());

    let again = new_client(&base)
        .test_login(handle, &secret)
        .await
        .expect("second test login");
    assert_eq!(first.public_key, again.public_key, "same handle, same key");
    assert_eq!(&*first.private_key, &*again.private_key);
    assert!(!again.is_new_user, "the account already existed");

    // The returned private key really is this account's identity key: a
    // challenge-signature login with it lands on the same account.
    let scalar = hex_to_scalar(&first.private_key).expect("valid private key hex");
    let signer = IdentityChallengeSigner::from_scalar(&scalar).expect("valid scalar");
    let identity = new_client(&base)
        .login_identity(&signer)
        .await
        .expect("identity login with the test key");
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

#[tokio::test]
async fn siwe_secondary_surface_is_reachable_and_gated() {
    let base = require_stack!("siwe_secondary_surface_is_reachable_and_gated");
    let client = new_client(&base);

    // The nonce endpoint issues a fresh nonce.
    let nonce = client.siwe_challenge().await.expect("siwe nonce");
    assert!(!nonce.nonce.is_empty(), "a nonce is issued");

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

#[tokio::test]
async fn logout_revokes_the_refresh_token_server_side() {
    let base = require_stack!("logout_revokes_the_refresh_token_server_side");
    let (client, store) = client_with_store(&base);
    client
        .login_identity(&random_identity_signer())
        .await
        .expect("login");
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

// --- pin/name registry and quota (blueprint/api.md; #627) -------------------

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
    let targets = vec!["k51contractIdem".to_owned(), "bafyContractIdemC".to_owned()];
    client.retire(&targets).await.expect("first retire");
    client
        .retire(&targets)
        .await
        .expect("replayed retire is a no-op");
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
    alice
        .retire(&[shared.clone()])
        .await
        .expect("alice retires her row while bob still references the CID");
    bob.retire(&[shared])
        .await
        .expect("bob retires the last row");
}

/// Quota (blueprint/api.md): hosted accounts are authoritative (`advisory:
/// false`) with a positive limit; a BYO account's rows are advisory
/// (`advisory: true`, quota always allows). The flag flips live with the BYO
/// toggle.
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

    // Enabling BYO makes the account's rows advisory: quota always allows.
    client.set_byo(true).await.expect("enable BYO");
    let byo = client.quota().await.expect("byo quota");
    assert!(byo.advisory, "a BYO account's quota is advisory");
    assert_eq!(
        byo.limit_bytes, hosted.limit_bytes,
        "the limit is unchanged"
    );

    // Toggling BYO back restores the authoritative posture.
    client.set_byo(false).await.expect("disable BYO");
    let restored = client.quota().await.expect("restored quota");
    assert!(
        !restored.advisory,
        "clearing BYO restores authoritative quota"
    );
}
