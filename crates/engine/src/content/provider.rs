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
use core::net::{Ipv4Addr, Ipv6Addr};

use zeroize::Zeroizing;

use crate::seams::{Http, HttpMethod, HttpRequest};

const AUTHORIZATION: &str = "Authorization";

/// The cloud metadata service, which no IPFS provider serves: the IPv4
/// link-local address and the IPv6 address AWS answers on.
const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);

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

/// Why a provider connection test did not succeed. The first four are policy
/// verdicts reached before any request is issued, kept distinct so a host can
/// say which rule refused the config instead of showing a bare failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The endpoint is not an absolute `http(s)` URL with a host-and-port
    /// authority — a member-supplied string must not reach the Http seam as a
    /// `file:`/relative/hostless target (SSRF and scheme-exfiltration surface).
    InvalidEndpoint,
    /// Plaintext `http://` to a host that is not a literal loopback address:
    /// the probe carries the member's bearer, so the credential would cross the
    /// network in the clear.
    InsecureTransport,
    /// The endpoint names the cloud metadata service.
    BlockedAddress,
    /// The access token carries bytes a header value may not.
    InvalidCredential,
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
/// The member-controlled config passes [`validate_byo_config`] before it reaches
/// the seam. A transport failure is [`ProviderError::Unreachable`]; a non-2xx is
/// [`ProviderError::Rejected`].
pub async fn test_connection(
    config: &ByoIpfsConfig,
    http: &impl Http,
) -> Result<(), ProviderError> {
    validate_byo_config(config)?;
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

/// The one gate over a member's BYO config, run before anything it names
/// reaches the Http seam (blueprint/engine.md "Content plane"). A member types
/// this config, but the vault settings record also carries it back off the
/// network, so the same bar applies in both directions.
pub fn validate_byo_config(config: &ByoIpfsConfig) -> Result<(), ProviderError> {
    validate_endpoint(&config.endpoint)?;
    match &config.access_token {
        // The token is spliced into a header value verbatim, so it may carry
        // only the bytes one admits — a control character would inject a header.
        Some(token) if !token.bytes().all(is_header_value_byte) => {
            Err(ProviderError::InvalidCredential)
        }
        _ => Ok(()),
    }
}

/// Require an absolute `http(s)` URL whose authority is a host and optional
/// port, then hold the host to the transport and address policy. A lightweight
/// scheme+authority check (the engine has no URL parser): it rejects other
/// schemes (`file:`, `ftp:`, …), scheme-less or relative strings, and a hostless
/// `http:///path`, closing the scheme-exfiltration / SSRF surface a raw member
/// string would open.
///
/// The endpoint is spliced into a request URL, so the authority is restricted to
/// the bytes a host and port may contain: whitespace, a control character, or
/// URL syntax (`@`, `?`, `#`, `\`) could reshape the request target or inject a
/// header, and which one happens would depend on the host `Http` implementation.
/// That decision does not belong to the seam.
fn validate_endpoint(endpoint: &str) -> Result<(), ProviderError> {
    let lower = endpoint.to_ascii_lowercase();
    let (tls, authority) = match lower.strip_prefix("https://") {
        Some(rest) => (true, rest),
        None => (
            false,
            lower
                .strip_prefix("http://")
                .ok_or(ProviderError::InvalidEndpoint)?,
        ),
    };
    // A host must follow the scheme (not empty, not straight into a path).
    let host_port = authority.split('/').next().unwrap_or_default();
    if host_port.is_empty() || !host_port.bytes().all(is_authority_byte) {
        return Err(ProviderError::InvalidEndpoint);
    }
    // The path may still not carry URL syntax that reshapes the target.
    if authority.bytes().any(|b| !is_path_byte(b)) {
        return Err(ProviderError::InvalidEndpoint);
    }
    let host = host_of(host_port)?;
    if is_metadata_literal(host) {
        return Err(ProviderError::BlockedAddress);
    }
    if !tls && !is_loopback_literal(host) {
        return Err(ProviderError::InsecureTransport);
    }
    Ok(())
}

/// The host of a `host`, `host:port`, `[v6]` or `[v6]:port` authority. Fail
/// closed: an authority that does not split cleanly is refused, never guessed,
/// because everything downstream keys off the host it yields.
fn host_of(authority: &str) -> Result<&str, ProviderError> {
    let bad = || ProviderError::InvalidEndpoint;
    let (host, port) = match authority.strip_prefix('[') {
        Some(rest) => {
            let (host, tail) = rest.split_once(']').ok_or_else(bad)?;
            // A bracketed authority holds an IPv6 literal and nothing else.
            host.parse::<Ipv6Addr>().map_err(|_| bad())?;
            match tail {
                "" => (host, None),
                _ => (host, Some(tail.strip_prefix(':').ok_or_else(bad)?)),
            }
        }
        None => {
            let (host, port) = match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority, None),
            };
            if host.is_empty() || host.contains(['[', ']']) {
                return Err(bad());
            }
            (host, port)
        }
    };
    if port.is_some_and(|p| p.parse::<u16>().is_err()) {
        return Err(bad());
    }
    Ok(host)
}

/// Loopback decided from the literal alone. The engine has no resolver and does
/// not acquire one for this: a name's address is the host's to resolve at
/// request time, so a resolved verdict here would be a TOCTOU hole.
fn is_loopback_literal(host: &str) -> bool {
    host == "localhost"
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
        || host.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback())
}

fn is_metadata_literal(host: &str) -> bool {
    host.parse::<Ipv4Addr>().is_ok_and(|ip| ip == METADATA_V4)
        || host
            .parse::<Ipv6Addr>()
            .is_ok_and(|ip| ip == METADATA_V6 || ip.to_ipv4() == Some(METADATA_V4))
}

/// The bytes a host-and-port may contain: letters, digits, `-`, `.`, `:`, plus
/// `[`/`]` for an IPv6 literal.
fn is_authority_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b':' | b'[' | b']')
}

/// The bytes the trailing path may contain — everything the authority admits
/// plus the ordinary path characters, and nothing that redirects the request
/// (`@`, `?`, `#`, `\`) or that no URL may carry raw (controls, whitespace).
fn is_path_byte(b: u8) -> bool {
    is_authority_byte(b) || matches!(b, b'/' | b'_' | b'~' | b'%' | b'+' | b'=' | b'&' | b',')
}

/// The bytes an HTTP field value admits: visible ASCII plus space and tab.
fn is_header_value_byte(b: u8) -> bool {
    matches!(b, 0x20 | 0x09 | 0x21..=0x7e)
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
    fn an_endpoint_outside_the_policy_is_rejected_before_any_request() {
        use ProviderError::{BlockedAddress, InsecureTransport, InvalidEndpoint};

        let http = ScriptedHttp::default();
        for (bad, verdict) in [
            ("file:///etc/passwd", InvalidEndpoint),
            ("ftp://host/x", InvalidEndpoint),
            ("ipfs.member.test", InvalidEndpoint), // no scheme
            ("http://", InvalidEndpoint),          // no host
            ("https:///pins", InvalidEndpoint),    // hostless
            ("", InvalidEndpoint),
            // A record-sourced endpoint is spliced into a request URL, so the
            // authority may carry only host-and-port bytes: no control
            // characters, no whitespace, and no syntax that redirects the
            // target or injects a header.
            ("http://host\r\nX-Evil: 1", InvalidEndpoint),
            ("http://host with space", InvalidEndpoint),
            ("http://user@evil.test", InvalidEndpoint),
            ("http://host/path?query", InvalidEndpoint),
            ("http://host/path#frag", InvalidEndpoint),
            ("http://host\\evil.test", InvalidEndpoint),
            // An authority that does not split into host and port is refused
            // rather than guessed at, because the policy below keys off the host.
            ("http://[::1", InvalidEndpoint),
            ("http://[kubo.example]", InvalidEndpoint),
            ("http://[::1]x", InvalidEndpoint),
            ("http://::1:5001", InvalidEndpoint),
            ("https://kubo.example:no", InvalidEndpoint),
            ("https://kubo.example:99999", InvalidEndpoint),
            // Plaintext carries the bearer in the clear: only a literal
            // loopback host may use it, and a name is never one.
            ("http://kubo.example", InsecureTransport),
            ("http://127.0.0.1.evil.test", InsecureTransport),
            ("http://localhost.evil.test", InsecureTransport),
            ("http://192.168.1.9:5001", InsecureTransport),
            // The cloud metadata service, under either scheme and in the IPv6
            // spellings of the same address.
            ("http://169.254.169.254", BlockedAddress),
            ("https://169.254.169.254/pins", BlockedAddress),
            ("https://[::ffff:169.254.169.254]", BlockedAddress),
            ("https://[fd00:ec2::254]", BlockedAddress),
        ] {
            let cfg = ByoIpfsConfig {
                endpoint: bad.into(),
                kind: ByoKind::Psa,
                access_token: None,
            };
            assert_eq!(
                block_on(test_connection(&cfg, &http)).unwrap_err(),
                verdict,
                "{bad:?} must be rejected"
            );
        }
        assert!(
            http.requests().is_empty(),
            "a refused endpoint never reaches the seam"
        );
    }

    #[test]
    fn a_local_http_kubo_endpoint_is_allowed() {
        for host in [
            "127.0.0.1:5001",
            "127.1.2.3:5001",
            "localhost:5001",
            "[::1]",
        ] {
            let http = ScriptedHttp::default();
            http.enqueue_response(ok());
            let cfg = ByoIpfsConfig {
                endpoint: format!("http://{host}"),
                kind: ByoKind::Kubo,
                access_token: None,
            };
            block_on(test_connection(&cfg, &http)).unwrap();
            assert_eq!(http.requests()[0].url, format!("http://{host}/api/v0/id"));
        }
    }

    #[test]
    fn a_private_range_endpoint_over_tls_is_allowed() {
        let http = ScriptedHttp::default();
        http.enqueue_response(ok());
        let cfg = ByoIpfsConfig {
            endpoint: "https://192.168.1.9:5001".into(),
            kind: ByoKind::Kubo,
            access_token: None,
        };
        block_on(test_connection(&cfg, &http)).unwrap();
    }

    #[test]
    fn an_access_token_that_could_inject_a_header_is_refused() {
        let http = ScriptedHttp::default();
        for bad in ["tok\r\nX-Evil: 1", "tok\n", "tok\u{7f}"] {
            let cfg = ByoIpfsConfig {
                endpoint: "https://ipfs.member.test".into(),
                kind: ByoKind::Psa,
                access_token: Some(Zeroizing::new(bad.to_owned())),
            };
            assert_eq!(
                block_on(test_connection(&cfg, &http)).unwrap_err(),
                ProviderError::InvalidCredential,
                "{bad:?} must be rejected"
            );
        }
        assert!(
            http.requests().is_empty(),
            "a refused credential never reaches the seam"
        );
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
