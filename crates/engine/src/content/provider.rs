//! The pin-provider layer — hosted / external / dual placement and the
//! engine-side BYO connection test over the `Http` seam (blueprint/engine.md
//! "Content plane").
//!
//! This module owns the placement decision surface and the BYO config type plus
//! its engine-side reachability probe. Registration and the publish pipeline
//! (register-first, every mode) live in the net plane; sealing the config into
//! vault settings is the payload/vault-settings slice — the type here is the
//! plaintext it seals.

use core::fmt;

use zeroize::Zeroizing;

use crate::seams::{Http, HttpMethod, HttpRequest};

const AUTHORIZATION: &str = "Authorization";

/// Where a version's bytes are pinned (#34 D1). Every mode still registers with
/// the API for union-liveness accounting; only the byte destination differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// CipherBox's hosted pin store (the default). Quota is authoritative.
    Hosted,
    /// The member's own provider only. Quota is advisory.
    External,
    /// Both hosted and the member's own provider.
    Dual,
}

/// The kind of member-supplied IPFS provider, which fixes the reachability
/// probe (their APIs differ).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ByoKind {
    /// A Kubo RPC endpoint (`/api/v0`).
    Kubo,
    /// An IPFS Pinning Service API endpoint (`/pins`).
    Psa,
    /// A Pinata endpoint.
    Pinata,
}

/// A member's bring-your-own IPFS provider config. Stays sealed in vault
/// settings (blueprint/engine.md); this is the plaintext the seal wraps. The
/// access token is a credential: held in a zeroizing buffer and redacted from
/// `Debug` (security rule 2).
#[derive(Clone, PartialEq, Eq)]
pub struct ByoIpfsConfig {
    /// The provider API base URL.
    pub endpoint: String,
    /// The provider kind, selecting the reachability probe.
    pub kind: ByoKind,
    /// Bearer credential, when the provider requires one (PSA/Pinata always;
    /// Kubo when fronted by an auth proxy). Zeroized on drop, never logged.
    pub access_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for ByoIpfsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ByoIpfsConfig")
            .field("endpoint", &self.endpoint)
            .field("kind", &self.kind)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

/// Why a provider connection test did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The endpoint is not an absolute `http(s)` URL with a host, so it is
    /// rejected before any request is issued — a member-supplied string must not
    /// reach the Http seam as a `file:`/relative/hostless target (SSRF and
    /// scheme-exfiltration surface).
    InvalidEndpoint,
    /// The provider could not be reached (transport-level failure).
    Unreachable,
    /// The provider was reached but rejected the probe (bad endpoint, auth
    /// failure, or an unhealthy node): a non-2xx status.
    Rejected {
        /// The status the provider returned.
        status: u16,
    },
}

/// Test that a member's BYO provider is reachable and authenticated, engine-side
/// over the Http seam. Issues the provider's standard health/auth probe and
/// treats any 2xx as success.
///
/// The member-controlled endpoint passes [`validate_endpoint`] before it reaches
/// the seam. A transport failure is [`ProviderError::Unreachable`]; a non-2xx is
/// [`ProviderError::Rejected`].
pub async fn test_connection(
    config: &ByoIpfsConfig,
    http: &impl Http,
) -> Result<(), ProviderError> {
    validate_endpoint(&config.endpoint)?;
    let request = probe_request(config);
    let response = http
        .send(request)
        .await
        .map_err(|_| ProviderError::Unreachable)?;
    if (200..300).contains(&response.status) {
        Ok(())
    } else {
        Err(ProviderError::Rejected {
            status: response.status,
        })
    }
}

/// Require an absolute `http(s)` URL with a non-empty host before the endpoint
/// reaches the Http seam. A lightweight scheme+authority check (the engine has
/// no URL parser): it rejects other schemes (`file:`, `ftp:`, …), scheme-less or
/// relative strings, and a hostless `http:///path`, closing the
/// scheme-exfiltration / SSRF surface a raw member string would open.
pub fn validate_endpoint(endpoint: &str) -> Result<(), ProviderError> {
    let lower = endpoint.to_ascii_lowercase();
    let authority = lower
        .strip_prefix("https://")
        .or_else(|| lower.strip_prefix("http://"));
    match authority {
        // A host must follow the scheme (not empty, not straight into a path).
        Some(rest) if !rest.is_empty() && !rest.starts_with('/') => Ok(()),
        _ => Err(ProviderError::InvalidEndpoint),
    }
}

/// The per-kind reachability probe. The endpoints are each provider's standard
/// identity/auth check: Kubo `POST /api/v0/id`, PSA `GET /pins?limit=1`, Pinata
/// `GET /data/testAuthentication`.
fn probe_request(config: &ByoIpfsConfig) -> HttpRequest {
    let base = config.endpoint.trim_end_matches('/');
    let (method, path) = match config.kind {
        ByoKind::Kubo => (HttpMethod::Post, "/api/v0/id"),
        ByoKind::Psa => (HttpMethod::Get, "/pins?limit=1"),
        ByoKind::Pinata => (HttpMethod::Get, "/data/testAuthentication"),
    };
    let mut headers = Vec::new();
    if let Some(token) = &config.access_token {
        headers.push((
            AUTHORIZATION.to_owned(),
            format!("Bearer {}", token.as_str()),
        ));
    }
    HttpRequest {
        method,
        url: format!("{base}{path}"),
        headers,
        body: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seams::HttpResponse;
    use crate::testkit::block_on;
    use crate::testkit::fakes::ScriptedHttp;

    fn config(kind: ByoKind, token: Option<&str>) -> ByoIpfsConfig {
        ByoIpfsConfig {
            endpoint: "https://ipfs.member.test/".into(),
            kind,
            access_token: token.map(|t| Zeroizing::new(t.to_owned())),
        }
    }

    fn ok() -> HttpResponse {
        HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: b"{}".to_vec(),
        }
    }

    #[test]
    fn kubo_probe_posts_the_id_endpoint() {
        let http = ScriptedHttp::default();
        http.enqueue_response(ok());
        block_on(test_connection(&config(ByoKind::Kubo, None), &http)).unwrap();
        let request = &http.requests()[0];
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(request.url, "https://ipfs.member.test/api/v0/id");
    }

    #[test]
    fn psa_probe_gets_pins_with_the_bearer() {
        let http = ScriptedHttp::default();
        http.enqueue_response(ok());
        block_on(test_connection(
            &config(ByoKind::Psa, Some("psa-key")),
            &http,
        ))
        .unwrap();
        let request = &http.requests()[0];
        assert_eq!(request.method, HttpMethod::Get);
        assert_eq!(request.url, "https://ipfs.member.test/pins?limit=1");
        assert!(
            request
                .headers
                .iter()
                .any(|(n, v)| n == AUTHORIZATION && v == "Bearer psa-key")
        );
    }

    #[test]
    fn pinata_probe_hits_test_authentication() {
        let http = ScriptedHttp::default();
        http.enqueue_response(ok());
        block_on(test_connection(
            &config(ByoKind::Pinata, Some("pin")),
            &http,
        ))
        .unwrap();
        assert_eq!(
            http.requests()[0].url,
            "https://ipfs.member.test/data/testAuthentication"
        );
    }

    #[test]
    fn non_2xx_is_rejected_with_the_status() {
        let http = ScriptedHttp::default();
        http.enqueue_response(HttpResponse {
            status: 401,
            headers: Vec::new(),
            body: Vec::new(),
        });
        let err = block_on(test_connection(&config(ByoKind::Psa, Some("bad")), &http)).unwrap_err();
        assert_eq!(err, ProviderError::Rejected { status: 401 });
    }

    #[test]
    fn transport_failure_is_unreachable() {
        let http = ScriptedHttp::default();
        http.enqueue_error(crate::seams::SeamError::new("dns failure"));
        let err = block_on(test_connection(&config(ByoKind::Kubo, None), &http)).unwrap_err();
        assert_eq!(err, ProviderError::Unreachable);
    }

    #[test]
    fn a_non_http_or_hostless_endpoint_is_rejected_before_any_request() {
        let http = ScriptedHttp::default();
        for bad in [
            "file:///etc/passwd",
            "ftp://host/x",
            "ipfs.member.test", // no scheme
            "http://",          // no host
            "https:///pins",    // hostless
            "",
        ] {
            let cfg = ByoIpfsConfig {
                endpoint: bad.into(),
                kind: ByoKind::Psa,
                access_token: None,
            };
            assert_eq!(
                block_on(test_connection(&cfg, &http)).unwrap_err(),
                ProviderError::InvalidEndpoint,
                "{bad:?} must be rejected"
            );
        }
        assert!(
            http.requests().is_empty(),
            "an invalid endpoint never reaches the seam"
        );
    }

    #[test]
    fn a_local_http_kubo_endpoint_is_allowed() {
        let http = ScriptedHttp::default();
        http.enqueue_response(ok());
        let cfg = ByoIpfsConfig {
            endpoint: "http://127.0.0.1:5001".into(),
            kind: ByoKind::Kubo,
            access_token: None,
        };
        block_on(test_connection(&cfg, &http)).unwrap();
        assert_eq!(http.requests()[0].url, "http://127.0.0.1:5001/api/v0/id");
    }

    #[test]
    fn debug_redacts_the_access_token() {
        let cfg = config(ByoKind::Pinata, Some("super-secret-jwt"));
        let debug = format!("{cfg:?}");
        assert!(
            !debug.contains("super-secret-jwt"),
            "token must never render"
        );
        assert!(debug.contains("<redacted>"));
    }
}
