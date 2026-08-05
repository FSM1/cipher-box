//! The pin-provider layer — block dispatch to a member's own IPFS provider and
//! the engine-side BYO connection test, both over the `Http` seam
//! (blueprint/engine.md "Content plane").
//!
//! This module owns the BYO config type, its engine-side reachability probe,
//! and the concrete block dispatch each provider kind takes. Which of them a
//! write uses is the placement decision, which reads a vault settings load and
//! so lives with it (`crate::settings`).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use cipherbox_core::content::{
    CONTENT_CID_CODEC, decode_content_cid_str, encode_content_cid_str, is_wellformed_content_cid,
};
use zeroize::Zeroizing;

use crate::content::DAG_ROOT_CODEC;
use crate::seams::{
    CappedFetchError, Http, HttpCredentials, HttpMethod, HttpRequest, HttpResponse,
};

/// Deadline for a BYO-provider reachability probe: an unresponsive endpoint
/// must read as unreachable rather than hang the settings flow.
const PROBE_TIMEOUT_MS: u64 = 10_000;

/// Deadline for one block placed on a member's provider. Longer than the
/// settings-flow probe above: this one moves up to a whole block.
const PLACEMENT_TIMEOUT_MS: u64 = 60_000;

/// Ceiling on what a BYO provider may answer with. The endpoint is
/// member-supplied and answers over the network, so an uncapped read lets it
/// size this process's memory. Every reply these requests have a use for is a
/// status line and a small JSON object; Kubo's newline-delimited `block/put`
/// stream is the largest, one short object per block put.
const MAX_PROVIDER_RESPONSE_BYTES: usize = 64 * 1024;

const AUTHORIZATION: &str = "Authorization";
const CONTENT_TYPE: &str = "Content-Type";
const APPLICATION_JSON: &str = "application/json";

/// The cloud metadata service, which no IPFS provider serves: the link-local
/// address in the two IPv6 spellings `to_canonical` does not fold, and the IPv6
/// address AWS answers on.
const METADATA: [IpAddr; 3] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0xa9fe, 0xa9fe)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254)),
];

/// Where a version's bytes are pinned (#34 D1). Every mode still registers with
/// the API for union-liveness accounting; only the byte destination differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinMode {
    /// CipherBox's hosted pin store (the default). Quota is authoritative.
    Hosted,
    /// The member's own provider only. No content block reaches the hosted
    /// store; record heads and registration still do.
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

/// Place one already-addressed block on the member's own provider. `cid` must
/// be the block's own content address, which the caller has already verified
/// (`Drain::staged_block`).
///
/// Kubo takes the bytes under exactly that address — `block/put` under the CID's
/// own multicodec and the frozen BLAKE3-256 framing. PSA and Pinata have no byte
/// ingress that preserves an address: they are asked to pin the CID and fetch it
/// themselves.
pub(crate) async fn place_block(
    config: &ByoIpfsConfig,
    cid: &[u8],
    block: &[u8],
    http: &impl Http,
) -> Result<(), ProviderError> {
    validate_byo_config(config)?;
    let address = content_address(cid)?;
    let request = match config.kind {
        ByoKind::Kubo => kubo_block_put(config, &address, block),
        ByoKind::Psa => pin_by_cid(config, "/pins", "cid", &address.cid),
        ByoKind::Pinata => pin_by_cid(config, "/pinning/pinByHash", "hashToPin", &address.cid),
    };
    let response = capped(http, request).await?;
    if !(200..300).contains(&response.status) {
        return Err(ProviderError::Rejected {
            status: response.status,
        });
    }
    match config.kind {
        ByoKind::Kubo => kubo_stored_address(&response.body, cid),
        ByoKind::Psa | ByoKind::Pinata => Ok(()),
    }
}

/// One request to a member's provider, its response bounded by
/// [`MAX_PROVIDER_RESPONSE_BYTES`]. An over-cap body is
/// [`ProviderError::NoVerdict`]: the transport aborted before the answer was
/// whole, so nothing in it says what the provider did.
async fn capped(http: &impl Http, request: HttpRequest) -> Result<HttpResponse, ProviderError> {
    http.send_capped(request, MAX_PROVIDER_RESPONSE_BYTES)
        .await
        .map_err(|error| match error {
            CappedFetchError::Transport(_) => ProviderError::Unreachable,
            CappedFetchError::BodyTooLarge { .. } => ProviderError::NoVerdict,
        })
}

/// One block's content address in the two spellings a provider request needs.
struct ContentAddress {
    cid: String,
    /// The Kubo `cid-codec` name for the CID's own multicodec.
    codec: &'static str,
}

/// Read a block's address, fail-closed on anything outside the two frozen
/// content-plane shapes. Core's own framing predicate runs first: it is what
/// [`encode_content_cid_str`] asserts on, so screening the codec alone would
/// turn a malformed address into a panic instead of this verdict.
fn content_address(cid: &[u8]) -> Result<ContentAddress, ProviderError> {
    if !is_wellformed_content_cid(cid) {
        return Err(ProviderError::MalformedBlockAddress);
    }
    let codec = match cid[1] {
        CONTENT_CID_CODEC => "raw",
        DAG_ROOT_CODEC => "dag-cbor",
        _ => return Err(ProviderError::MalformedBlockAddress),
    };
    Ok(ContentAddress {
        cid: encode_content_cid_str(cid),
        codec,
    })
}

/// `block/put` under the block's own codec and the frozen BLAKE3-256 framing,
/// pinned in the same call, so the member's node addresses it exactly as the
/// engine does.
fn kubo_block_put(config: &ByoIpfsConfig, address: &ContentAddress, block: &[u8]) -> HttpRequest {
    // Derived from the block's own address, so the delimiter cannot occur in the
    // payload it frames: that would take a block carrying the base32 of its own
    // BLAKE3 digest, which is a preimage. 62 bytes of base32 and `-`, inside RFC
    // 2046's 70-character cap.
    let boundary = format!("cb-{}", address.cid);
    let head = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"data\"; filename=\"blob\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n"
    );
    let tail = format!("\r\n--{boundary}--\r\n");
    let mut body = Vec::with_capacity(head.len() + block.len() + tail.len());
    body.extend_from_slice(head.as_bytes());
    body.extend_from_slice(block);
    body.extend_from_slice(tail.as_bytes());
    let codec = address.codec;
    HttpRequest {
        method: HttpMethod::Post,
        // A DAG root inlines a CID per leaf, so it passes Kubo's 1 MiB
        // block/put advisory well before the flat-DAG ceiling does. The block is
        // content-addressed and self-verifying, so the advice does not apply.
        url: format!(
            "{}/api/v0/block/put\
             ?cid-codec={codec}&mhtype=blake3&mhlen=32&pin=true&allow-big-block=true",
            base(config)
        ),
        headers: headers(
            config,
            Some(format!("multipart/form-data; boundary={boundary}")),
        ),
        body: Some(body),
        credentials: HttpCredentials::Omit,
        timeout_ms: Some(PLACEMENT_TIMEOUT_MS),
    }
}

/// Ask a pin-by-CID service to pin an address it fetches itself.
fn pin_by_cid(config: &ByoIpfsConfig, path: &str, field: &str, cid: &str) -> HttpRequest {
    HttpRequest {
        method: HttpMethod::Post,
        url: format!("{}{path}", base(config)),
        headers: headers(config, Some(APPLICATION_JSON.to_owned())),
        // The CID is base32 alphanumerics, so it needs no JSON escaping.
        body: Some(format!("{{\"{field}\":\"{cid}\"}}").into_bytes()),
        credentials: HttpCredentials::Omit,
        timeout_ms: Some(PLACEMENT_TIMEOUT_MS),
    }
}

/// The address Kubo reports storing the block under, held to the caller's. The
/// compare accepts only the canonical base32 spelling `encode_content_cid_str`
/// sent — the strict `decode_content_cid_str` is deliberately the one decoder
/// the content plane has, and widening it to every multibase alphabet to read a
/// provider's echo would enlarge what a remote can steer for no safety gained.
///
/// This catches a node that re-chunked or hashed the block differently — a
/// misconfiguration, not an attack. A provider can always claim an address it
/// does not serve; what makes a read safe is the reader's own `verify_cid`.
///
/// Kubo streams newline-delimited JSON; a trailing error object parses but
/// carries no `Key`, so an absent one is no usable answer.
fn kubo_stored_address(body: &[u8], expected: &[u8]) -> Result<(), ProviderError> {
    #[derive(serde::Deserialize)]
    struct BlockPut {
        #[serde(rename = "Key")]
        key: String,
    }
    let last = core::str::from_utf8(body)
        .ok()
        .and_then(|body| body.trim().lines().next_back().map(str::to_owned));
    let stored = last
        .and_then(|line| serde_json::from_str::<BlockPut>(&line).ok())
        .ok_or(ProviderError::NoVerdict)?;
    match decode_content_cid_str(&stored.key) {
        Ok(stored) if stored == expected => Ok(()),
        _ => Err(ProviderError::AddressMismatch),
    }
}

fn base(config: &ByoIpfsConfig) -> &str {
    config.endpoint.trim_end_matches('/')
}

/// The bearer the config carries, plus a content type when the request has a
/// body. The configured access token is the only credential a BYO endpoint gets.
fn headers(config: &ByoIpfsConfig, content_type: Option<String>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    if let Some(token) = &config.access_token {
        headers.push((
            AUTHORIZATION.to_owned(),
            format!("Bearer {}", token.as_str()),
        ));
    }
    if let Some(content_type) = content_type {
        headers.push((CONTENT_TYPE.to_owned(), content_type));
    }
    headers
}

/// Why a provider connection test did not succeed. The first four are policy
/// verdicts reached before any request is issued, kept distinct so a host can
/// say which rule refused the config instead of showing a bare failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    /// The endpoint is not an absolute `http(s)` URL whose authority is
    /// host-and-port bytes. It is spliced into a request URL, so a `file:`,
    /// relative or hostless target, or one carrying whitespace, a control
    /// character or URL syntax (`@`, `?`, `#`, `\`), could reshape the request
    /// or inject a header — and which one happens would depend on the host
    /// `Http` implementation. That decision does not belong to the seam.
    InvalidEndpoint,
    /// Plaintext `http://` to a host that is not loopback: the probe carries
    /// the member's bearer, so the credential would cross the network in the
    /// clear.
    InsecureTransport,
    /// The endpoint names the cloud metadata service.
    BlockedAddress,
    /// The access token carries bytes a header value may not.
    InvalidCredential,
    /// The provider could not be reached (transport-level failure).
    Unreachable,
    /// The provider answered, but with nothing that says what it did.
    NoVerdict,
    /// The provider was reached but rejected the request (bad endpoint, auth
    /// failure, or an unhealthy node): a non-2xx status.
    Rejected {
        /// The status the provider returned.
        status: u16,
    },
    /// The block's address is not one of the two frozen content-plane shapes,
    /// so no provider can be told the codec to store it under.
    MalformedBlockAddress,
    /// The provider stored the block under an address other than the one it was
    /// given, so the published record would name bytes it does not serve.
    AddressMismatch,
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
    let response = capped(http, probe_request(config)).await?;
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
        // The token is spliced into a header value verbatim, so a control
        // character in it would inject a header. A present-but-empty one is an
        // `Authorization: Bearer ` no provider accepts; `None` is how a
        // credential-less provider is spelled.
        Some(token) if token.is_empty() || !token.bytes().all(is_bearer_byte) => {
            Err(ProviderError::InvalidCredential)
        }
        _ => Ok(()),
    }
}

/// Require an absolute `http(s)` URL whose authority is a host and optional
/// port, then hold the host to the transport and address policy
/// (blueprint/engine.md "Content plane"). A lightweight scheme+authority check —
/// the engine has no URL parser — enforcing the byte rule
/// [`ProviderError::InvalidEndpoint`] states.
fn validate_endpoint(endpoint: &str) -> Result<(), ProviderError> {
    let lower = endpoint.to_ascii_lowercase();
    let (tls, authority) = if let Some(rest) = lower.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = lower.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(ProviderError::InvalidEndpoint);
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
    let (host, ip) = host_of(host_port)?;
    if ip.is_some_and(|ip| METADATA.contains(&ip)) {
        return Err(ProviderError::BlockedAddress);
    }
    if !tls && !is_loopback(host, ip) {
        return Err(ProviderError::InsecureTransport);
    }
    Ok(())
}

/// The host of a `host`, `host:port`, `[v6]` or `[v6]:port` authority, with the
/// address it denotes when it is a literal — IPv4-mapped forms folded, so one
/// address gets one verdict. Fail closed: an authority that does not split
/// cleanly is refused, never guessed, because the policy keys off the host.
fn host_of(authority: &str) -> Result<(&str, Option<IpAddr>), ProviderError> {
    let bad = || ProviderError::InvalidEndpoint;
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest.split_once(']').ok_or_else(bad)?;
        // A bracketed authority holds an IPv6 literal and nothing else.
        if !host.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
            return Err(bad());
        }
        match tail {
            "" => (host, None),
            _ => (host, Some(tail.strip_prefix(':').ok_or_else(bad)?)),
        }
    } else if let Some((host, port)) = authority.split_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    if host.is_empty() || host.contains(['[', ']']) {
        return Err(bad());
    }
    if port.is_some_and(|p| p.parse::<u16>().is_err()) {
        return Err(bad());
    }
    let ip = host.parse::<IpAddr>().ok().map(|ip| ip.to_canonical());
    if ip.is_none() && !is_dns_name(host) {
        return Err(bad());
    }
    Ok((host, ip))
}

/// A host the engine and the seam's URL parser will read the same way. Core's
/// address parser is strict, but a WHATWG one reads `0xa9fea9fe` and
/// `0251.0376.0251.0376` as addresses — so a name whose last label could be
/// read as a number is refused rather than classified as a name here and an
/// address there.
fn is_dns_name(host: &str) -> bool {
    let shaped = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    };
    let last = host.rsplit('.').next().unwrap_or_default();
    host.len() <= 253
        && host.split('.').all(shaped)
        && !last.starts_with("0x")
        && !last.bytes().all(|b| b.is_ascii_digit())
}

/// Loopback decided without a resolver: a literal loopback address, or the name
/// RFC 6761 reserves for one. Every other name is treated as off-host, because
/// its address is the host's to resolve at request time and a resolved verdict
/// here would be a TOCTOU hole.
fn is_loopback(host: &str, ip: Option<IpAddr>) -> bool {
    host == "localhost" || ip.is_some_and(|ip| ip.is_loopback())
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

/// The bytes a bearer credential admits: visible ASCII, the header-value set
/// minus the whitespace no token carries.
fn is_bearer_byte(b: u8) -> bool {
    matches!(b, 0x21..=0x7e)
}

/// The per-kind reachability probe. The endpoints are each provider's standard
/// identity/auth check: Kubo `POST /api/v0/id`, PSA `GET /pins?limit=1`, Pinata
/// `GET /data/testAuthentication`.
fn probe_request(config: &ByoIpfsConfig) -> HttpRequest {
    let (method, path) = match config.kind {
        ByoKind::Kubo => (HttpMethod::Post, "/api/v0/id"),
        ByoKind::Psa => (HttpMethod::Get, "/pins?limit=1"),
        ByoKind::Pinata => (HttpMethod::Get, "/data/testAuthentication"),
    };
    HttpRequest {
        method,
        url: format!("{}{path}", base(config)),
        headers: headers(config, None),
        body: None,
        credentials: HttpCredentials::Omit,
        timeout_ms: Some(PROBE_TIMEOUT_MS),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cipherbox_core::content::compute_cid;

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
            ("http://host\r\nX-Evil: 1", InvalidEndpoint),
            ("http://host with space", InvalidEndpoint),
            ("http://user@evil.test", InvalidEndpoint),
            ("http://host/path?query", InvalidEndpoint),
            ("http://host/path#frag", InvalidEndpoint),
            ("http://host\\evil.test", InvalidEndpoint),
            ("http://[::1", InvalidEndpoint),
            ("http://[kubo.example]", InvalidEndpoint),
            ("http://[::1]x", InvalidEndpoint),
            ("http://::1:5001", InvalidEndpoint),
            ("https://kubo.example:no", InvalidEndpoint),
            ("https://kubo.example:99999", InvalidEndpoint),
            // A host the seam's URL parser would read as an address while this
            // gate reads it as a name is refused, not classified twice.
            ("https://2852039166", InvalidEndpoint),
            ("https://0251.0376.0251.0376", InvalidEndpoint),
            ("https://0xa9fea9fe", InvalidEndpoint),
            ("https://169.254.169.254.", InvalidEndpoint),
            ("https://-kubo.example", InvalidEndpoint),
            ("https://kubo..example", InvalidEndpoint),
            ("http://kubo.example", InsecureTransport),
            ("http://127.0.0.1.evil.test", InsecureTransport),
            ("http://localhost.evil.test", InsecureTransport),
            ("http://192.168.1.9:5001", InsecureTransport),
            // The metadata address is refused under either scheme, in each
            // address spelling of it (the numeric-host spellings above are
            // refused a step earlier, as unreadable rather than as metadata).
            ("http://169.254.169.254", BlockedAddress),
            ("https://169.254.169.254/pins", BlockedAddress),
            ("https://[::ffff:169.254.169.254]", BlockedAddress),
            ("https://[::169.254.169.254]", BlockedAddress),
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

    /// Plaintext to a loopback literal is the local-node case, and a private
    /// range over TLS is the LAN case: self-hosting is the feature.
    #[test]
    fn a_local_http_kubo_endpoint_is_allowed() {
        for endpoint in [
            "http://127.0.0.1:5001",
            "http://127.1.2.3:5001",
            "http://localhost:5001",
            "http://[::1]",
            "http://[::ffff:127.0.0.1]",
            "https://192.168.1.9:5001",
        ] {
            let http = ScriptedHttp::default();
            http.enqueue_response(ok());
            let cfg = ByoIpfsConfig {
                endpoint: endpoint.to_owned(),
                kind: ByoKind::Kubo,
                access_token: None,
            };
            block_on(test_connection(&cfg, &http)).unwrap();
            assert_eq!(http.requests()[0].url, format!("{endpoint}/api/v0/id"));
        }
    }

    #[test]
    fn an_access_token_that_could_inject_a_header_is_refused() {
        let http = ScriptedHttp::default();
        for bad in ["tok\r\nX-Evil: 1", "tok\n", "tok\u{7f}", "tok tok", ""] {
            assert_eq!(
                block_on(test_connection(&config(ByoKind::Psa, Some(bad)), &http)).unwrap_err(),
                ProviderError::InvalidCredential,
                "{bad:?} must be rejected"
            );
        }
        assert!(
            http.requests().is_empty(),
            "a refused credential never reaches the seam"
        );
    }

    fn leaf(bytes: &[u8]) -> Vec<u8> {
        compute_cid(CONTENT_CID_CODEC, bytes)
    }

    #[test]
    fn kubo_puts_the_block_under_its_own_codec_and_the_frozen_hash() {
        let http = ScriptedHttp::default();
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        let address = encode_content_cid_str(&cid);
        http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: format!("{{\"Key\":\"{address}\",\"Size\":17}}\n").into_bytes(),
        });
        block_on(place_block(
            &config(ByoKind::Kubo, Some("tok")),
            &cid,
            &block,
            &http,
        ))
        .unwrap();

        let request = &http.requests()[0];
        assert_eq!(request.method, HttpMethod::Post);
        assert_eq!(
            request.url,
            "https://ipfs.member.test/api/v0/block/put\
             ?cid-codec=raw&mhtype=blake3&mhlen=32&pin=true&allow-big-block=true"
        );
        let boundary = request
            .headers
            .iter()
            .find(|(name, _)| name == CONTENT_TYPE)
            .and_then(|(_, value)| value.split("boundary=").nth(1))
            .expect("the request declares its multipart boundary")
            .to_owned();
        let body = request.body.as_ref().expect("a block/put carries a body");
        assert!(
            body.windows(block.len()).any(|window| window == block),
            "the block rides the body verbatim"
        );
        assert!(
            body.ends_with(format!("\r\n--{boundary}--\r\n").as_bytes()),
            "and the body closes on the boundary"
        );
    }

    #[test]
    fn a_dag_root_is_put_under_the_dag_cbor_codec() {
        let http = ScriptedHttp::default();
        let block = b"root manifest".to_vec();
        let cid = compute_cid(DAG_ROOT_CODEC, &block);
        let address = encode_content_cid_str(&cid);
        http.enqueue_response(HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: format!("{{\"Key\":\"{address}\"}}").into_bytes(),
        });
        block_on(place_block(
            &config(ByoKind::Kubo, None),
            &cid,
            &block,
            &http,
        ))
        .unwrap();
        assert!(http.requests()[0].url.contains("cid-codec=dag-cbor"));
    }

    /// A provider that stored the block somewhere else would leave the published
    /// record naming bytes it does not serve, so the address it answers with is
    /// held to the one it was given.
    #[test]
    fn a_kubo_node_that_stored_the_block_elsewhere_is_a_failure() {
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        for body in [
            r#"{"Key":"bafkr4iamjdirj4vmqmpizgefavwr4nftqhx6p4bbqdigodc6ja2g3lwumi"}"#,
            // A trailing error object parses but names no address: a store
            // fault, never a disagreeing one.
            r#"{"Message":"boom","Type":"error"}"#,
            "",
        ] {
            let http = ScriptedHttp::default();
            http.enqueue_response(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
            });
            assert!(
                block_on(place_block(
                    &config(ByoKind::Kubo, None),
                    &cid,
                    &block,
                    &http
                ))
                .is_err(),
                "{body:?} must not read as a stored block"
            );
        }
    }

    #[test]
    fn a_pinning_service_is_asked_to_pin_the_address_it_fetches_itself() {
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        let address = encode_content_cid_str(&cid);
        for (kind, path, field) in [
            (ByoKind::Psa, "/pins", "cid"),
            (ByoKind::Pinata, "/pinning/pinByHash", "hashToPin"),
        ] {
            let http = ScriptedHttp::default();
            http.enqueue_response(ok());
            block_on(place_block(&config(kind, Some("tok")), &cid, &block, &http)).unwrap();
            let request = &http.requests()[0];
            assert_eq!(request.url, format!("https://ipfs.member.test{path}"));
            assert_eq!(
                request.body.as_deref(),
                Some(format!("{{\"{field}\":\"{address}\"}}").as_bytes()),
                "the request names the address and carries no block bytes"
            );
            assert!(
                request
                    .headers
                    .iter()
                    .any(|(n, v)| n == CONTENT_TYPE && v == APPLICATION_JSON)
            );
        }
    }

    #[test]
    fn a_provider_that_refuses_or_cannot_be_reached_is_classified() {
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        let http = ScriptedHttp::default();
        http.enqueue_response(HttpResponse {
            status: 507,
            headers: Vec::new(),
            body: Vec::new(),
        });
        assert_eq!(
            block_on(place_block(
                &config(ByoKind::Psa, Some("t")),
                &cid,
                &block,
                &http
            ))
            .unwrap_err(),
            ProviderError::Rejected { status: 507 }
        );
        let http = ScriptedHttp::default();
        http.enqueue_error(crate::seams::SeamError::new("connection refused"));
        assert_eq!(
            block_on(place_block(
                &config(ByoKind::Kubo, None),
                &cid,
                &block,
                &http
            ))
            .unwrap_err(),
            ProviderError::Unreachable
        );
    }

    /// The same gate the settings record passes, applied here because the
    /// endpoint and the bearer are spliced into this request too.
    #[test]
    fn a_config_the_seam_may_not_be_pointed_at_never_reaches_it() {
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        let http = ScriptedHttp::default();
        let bad = ByoIpfsConfig {
            endpoint: "http://169.254.169.254".into(),
            kind: ByoKind::Kubo,
            access_token: None,
        };
        assert_eq!(
            block_on(place_block(&bad, &cid, &block, &http)).unwrap_err(),
            ProviderError::BlockedAddress
        );
        assert!(http.requests().is_empty());
    }

    /// Every byte of the frozen framing, not just the codec: the address is
    /// rendered for the request, and core's renderer aborts rather than returns
    /// on a malformed one.
    #[test]
    fn a_block_address_outside_the_frozen_shapes_is_refused_before_the_seam() {
        let http = ScriptedHttp::default();
        let mutated = |index: usize, byte: u8| {
            let mut cid = leaf(b"x");
            cid[index] = byte;
            cid
        };
        for cid in [
            mutated(0, 0x02), // CID version
            mutated(1, 0x70), // dag-pb: not a content-plane codec
            mutated(2, 0x12), // sha2-256: not the frozen multihash
            mutated(3, 0x40), // a digest width the framing does not carry
            leaf(b"x")[..8].to_vec(),
            Vec::new(),
        ] {
            assert_eq!(
                block_on(place_block(&config(ByoKind::Kubo, None), &cid, b"x", &http)).unwrap_err(),
                ProviderError::MalformedBlockAddress,
                "{cid:02x?}"
            );
        }
        assert!(http.requests().is_empty());
    }

    /// The endpoint is member-supplied and answers over the network, so what it
    /// returns is bounded before it is read. An over-cap body is no answer at
    /// all, never bytes this process accumulates.
    #[test]
    fn an_over_cap_provider_body_is_no_verdict() {
        let oversized = || HttpResponse {
            status: 200,
            headers: Vec::new(),
            body: vec![b'{'; MAX_PROVIDER_RESPONSE_BYTES + 1],
        };
        let block = b"sealed leaf bytes".to_vec();
        let cid = leaf(&block);
        for kind in [ByoKind::Kubo, ByoKind::Psa, ByoKind::Pinata] {
            let http = ScriptedHttp::default();
            http.enqueue_response(oversized());
            assert_eq!(
                block_on(place_block(&config(kind, Some("tok")), &cid, &block, &http)).unwrap_err(),
                ProviderError::NoVerdict,
                "{kind:?}"
            );

            let http = ScriptedHttp::default();
            http.enqueue_response(oversized());
            assert_eq!(
                block_on(test_connection(&config(kind, Some("tok")), &http)).unwrap_err(),
                ProviderError::NoVerdict,
                "{kind:?}"
            );
        }
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
