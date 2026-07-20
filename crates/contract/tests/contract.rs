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
use cipherbox_engine::api::{ApiClient, ApiError, IdentityChallengeSigner};
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
