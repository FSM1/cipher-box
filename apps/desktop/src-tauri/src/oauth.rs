//! Native Google collection (ADR 0008 D3, blueprint/desktop.md "Tauri shell").
//!
//! Google Identity Services does not run in this webview, and the OAuth2 flow
//! it falls back to needs an `http(s)` `redirect_uri` — which a packaged Tauri
//! origin (`tauri://localhost`) is not, so the provider refuses it. The shell
//! therefore serves the callback itself, from a loopback listener on a port
//! pre-registered with the provider.
//!
//! The exchange is bounded on every axis: the redirect names the `127.0.0.1`
//! literal and the listener binds it, never the `localhost` name (RFC 8252
//! §8.3), a page nonce the callback document carries is required on the POST
//! that delivers the token, `state` binds the redirect to this request, and
//! both the whole exchange and each connection have absolute deadlines.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::Deserialize;
use tauri::{AppHandle, Url, WebviewUrl, WebviewWindow, WebviewWindowBuilder};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Callback ports, tried in order.
///
/// Each must be registered with the provider as an authorized redirect URI in
/// its `http://127.0.0.1:{port}/callback` form, so an exhausted list fails fast
/// rather than falling back to a random port that the provider would refuse.
const CALLBACK_PORTS: &[u16] = &[14200, 14201, 14202];

const CALLBACK_PATH: &str = "/callback";
const TOKEN_PATH: &str = "/token";

/// How long the whole exchange may take, counted from before the window opens.
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(120);

/// How long one connection may take to deliver its request, so a stalled peer
/// cannot starve the callback of the exchange deadline.
const CONNECTION_DEADLINE: Duration = Duration::from_secs(10);

/// Nothing the callback page sends approaches this; anything larger is refused
/// rather than buffered.
const MAX_REQUEST_BYTES: usize = 16 * 1024;

const AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// The only host this shell will open a window on.
const PROVIDER_HOST: &str = "accounts.google.com";

/// Window labels must be unique for the app's lifetime, and a label is reused
/// the moment a member retries a sign-in.
static CONSENT_WINDOWS: AtomicU64 = AtomicU64::new(0);

/// The secrets that bind one exchange: `state` travels through the provider and
/// comes back on the redirect, and `page_nonce` never leaves this machine and
/// gates the POST that carries the token.
struct Exchange {
    state: String,
    page_nonce: String,
    /// Required by the provider for an `id_token` response.
    oidc_nonce: String,
}

impl Exchange {
    fn new() -> Result<Self, String> {
        Ok(Self {
            state: random_hex()?,
            page_nonce: random_hex()?,
            oidc_nonce: random_hex()?,
        })
    }
}

/// Collects a Google ID token for the login flow to exchange with CipherBox.
#[tauri::command]
pub async fn collect_google_id_token(app: AppHandle, client_id: String) -> Result<String, String> {
    let (listener, _v6_guard) = bind_callback_listener().await?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("the callback listener has no address: {error}"))?
        .port();

    let exchange = Exchange::new()?;
    let url = authorize_url(&client_id, port, &exchange)?;
    let window = open_provider_window(&app, url)?;

    let outcome = tokio::time::timeout(EXCHANGE_DEADLINE, serve(listener, &exchange)).await;
    let _ = window.close();

    outcome.unwrap_or_else(|_| Err("the sign-in window timed out".to_string()))
}

/// Binds the first free pre-registered port on both loopback families.
///
/// The IPv6 bind is held for the exchange as defence in depth: the redirect
/// names the IPv4 literal, so a squatter on `[::1]` cannot be reached, but a
/// port answered by another process is refused rather than left in place. A
/// host with no IPv6 loopback at all has nothing to squat, so only a taken one
/// is fatal.
async fn bind_callback_listener() -> Result<(TcpListener, Option<TcpListener>), String> {
    for port in CALLBACK_PORTS {
        let Ok(listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, *port)).await else {
            continue;
        };
        return match TcpListener::bind((Ipv6Addr::LOCALHOST, *port)).await {
            Ok(guard) => Ok((listener, Some(guard))),
            Err(error) if error.kind() == ErrorKind::AddrInUse => Err(format!(
                "another process holds [::1]:{port}; close it and try again"
            )),
            Err(_) => Ok((listener, None)),
        };
    }
    Err(format!(
        "sign-in needs one of the ports {CALLBACK_PORTS:?}; close any other copy of CipherBox and try again"
    ))
}

/// The provider's authorize URL for this exchange.
///
/// Built by appending query pairs to a fixed base, so no value carried here can
/// move the request off that host.
fn authorize_url(client_id: &str, port: u16, exchange: &Exchange) -> Result<Url, String> {
    let mut url = Url::parse(AUTHORIZE_URL)
        .map_err(|error| format!("the authorize URL is not one: {error}"))?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", &redirect_uri(port))
        .append_pair("response_type", "id_token")
        .append_pair("scope", "openid email")
        .append_pair("nonce", &exchange.oidc_nonce)
        .append_pair("state", &exchange.state)
        .append_pair("prompt", "select_account");
    Ok(url)
}

/// The IP literal, never the `localhost` name: that name also resolves to
/// `::1`, which address-selection prefers and a separate bind can hold
/// (RFC 8252 §8.3).
fn redirect_uri(port: u16) -> String {
    format!("http://{}:{port}{CALLBACK_PATH}", Ipv4Addr::LOCALHOST)
}

/// Opens the consent screen in its own window.
///
/// Opened from here rather than `window.open()`, which is unreliable on Windows
/// WebView2. The scheme and host checks are the guard on what this shell will
/// ever navigate a window to.
fn open_provider_window(app: &AppHandle, url: Url) -> Result<WebviewWindow, String> {
    if url.scheme() != "https" {
        return Err("a sign-in window must be opened over https".to_string());
    }
    if url.host_str() != Some(PROVIDER_HOST) {
        return Err("that host is not a sign-in provider".to_string());
    }

    let label = format!(
        "google-consent-{}",
        CONSENT_WINDOWS.fetch_add(1, Ordering::Relaxed)
    );
    WebviewWindowBuilder::new(app, label, WebviewUrl::External(url))
        .title("Sign in with Google")
        .inner_size(520.0, 720.0)
        .center()
        .build()
        .map_err(|error| format!("the sign-in window would not open: {error}"))
}

/// What one delivered callback body means.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// The exchange is complete.
    Accepted(String),
    /// The exchange is over and failed.
    Refused(String),
    /// Not from the page this exchange served; answered and then forgotten.
    Ignored,
}

/// What the callback page POSTs back, having read the redirect fragment.
#[derive(Deserialize)]
struct Callback {
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

/// Judges one POST body against the exchange it claims to belong to.
fn verdict(body: &str, exchange: &Exchange) -> Verdict {
    let Ok(callback) = serde_json::from_str::<Callback>(body) else {
        return Verdict::Ignored;
    };
    // Gate on the nonce first: without it, any local process could post a token
    // of its own choosing into this member's sign-in.
    if callback.nonce.as_deref() != Some(&exchange.page_nonce) {
        return Verdict::Ignored;
    }
    if callback.state.as_deref() != Some(&exchange.state) {
        return Verdict::Refused("the sign-in reply does not belong to this attempt".to_string());
    }
    if let Some(error) = callback.error {
        return Verdict::Refused(refusal(&error));
    }
    match callback.id_token {
        Some(token) if !token.is_empty() => Verdict::Accepted(token),
        _ => Verdict::Refused("the provider returned no identity token".to_string()),
    }
}

/// The provider's own error code, rendered for the member.
fn refusal(code: &str) -> String {
    match code {
        "access_denied" => "sign-in was cancelled".to_string(),
        _ => "the provider refused this sign-in".to_string(),
    }
}

/// Serves the callback until the exchange settles.
async fn serve(listener: TcpListener, exchange: &Exchange) -> Result<String, String> {
    let page = callback_page(&exchange.page_nonce);

    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let Ok(Some(request)) = tokio::time::timeout(CONNECTION_DEADLINE, read(&mut stream)).await
        else {
            continue;
        };

        let Some((line, body)) = split(&request) else {
            respond(&mut stream, "400 Bad Request", "Bad request").await;
            continue;
        };

        if line.starts_with("GET ") && line.contains(CALLBACK_PATH) {
            respond(&mut stream, "200 OK", &page).await;
        } else if line.starts_with("POST ") && line.contains(TOKEN_PATH) {
            match verdict(body, exchange) {
                Verdict::Ignored => respond(&mut stream, "403 Forbidden", "Not this sign-in").await,
                Verdict::Accepted(token) => {
                    respond(&mut stream, "200 OK", DONE_PAGE).await;
                    return Ok(token);
                }
                Verdict::Refused(why) => {
                    respond(&mut stream, "200 OK", DONE_PAGE).await;
                    return Err(why);
                }
            }
        } else {
            respond(&mut stream, "404 Not Found", "Not found").await;
        }
    }
}

/// Reads one request, stopping at its declared length or the byte cap.
async fn read(stream: &mut TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    // Compared in bytes, which is what Content-Length declares; a lossy decode
    // widens every invalid sequence to three and would disagree with it.
    let mut body_starts_at = None;
    let mut declared = 0;

    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > MAX_REQUEST_BYTES {
            return None;
        }
        if body_starts_at.is_none() {
            if let Some(end) = raw.windows(4).position(|four| four == b"\r\n\r\n") {
                declared = content_length(&String::from_utf8_lossy(&raw[..end]));
                body_starts_at = Some(end + 4);
            }
        }
        if let Some(start) = body_starts_at {
            if raw.len() - start >= declared {
                break;
            }
        }
    }
    Some(String::from_utf8_lossy(&raw).into_owned())
}

/// Splits a request into its start line and its body.
fn split(request: &str) -> Option<(&str, &str)> {
    let (head, body) = request.split_once("\r\n\r\n")?;
    Some((head.lines().next().unwrap_or_default(), body))
}

/// The declared body length, or none declared.
fn content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

async fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// The page the redirect lands on. The token arrives in the URL fragment, which
/// no request carries, so the page reads it and posts it back with the nonce
/// that proves the post came from here.
fn callback_page(page_nonce: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CipherBox</title></head>
<body><p id="m">Completing sign-in…</p>
<script>
(function () {{
  var found = new URLSearchParams(window.location.hash.substring(1));
  fetch({TOKEN_PATH:?}, {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      id_token: found.get('id_token'),
      error: found.get('error'),
      state: found.get('state'),
      nonce: {page_nonce:?}
    }})
  }}).then(function () {{
    document.getElementById('m').textContent = 'Sign-in complete. You can close this window.';
  }});
}})();
</script></body></html>"#
    )
}

const DONE_PAGE: &str = r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>CipherBox</title></head>
<body><p>Sign-in complete. You can close this window.</p></body></html>"#;

/// 16 bytes of OS entropy, hex-encoded.
fn random_hex() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "this device has no entropy source".to_string())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange() -> Exchange {
        Exchange {
            state: "state-value".to_string(),
            page_nonce: "page-nonce".to_string(),
            oidc_nonce: "oidc-nonce".to_string(),
        }
    }

    fn body(fields: &str) -> String {
        format!("{{{fields}}}")
    }

    #[test]
    fn accepts_a_token_carrying_this_exchange_nonce_and_state() {
        let posted = body(r#""id_token":"a.b.c","state":"state-value","nonce":"page-nonce""#);
        assert_eq!(
            verdict(&posted, &exchange()),
            Verdict::Accepted("a.b.c".to_string())
        );
    }

    #[test]
    fn ignores_a_post_that_does_not_carry_the_page_nonce() {
        let posted = body(r#""id_token":"a.b.c","state":"state-value","nonce":"guessed""#);
        assert_eq!(verdict(&posted, &exchange()), Verdict::Ignored);

        let anonymous = body(r#""id_token":"a.b.c","state":"state-value""#);
        assert_eq!(verdict(&anonymous, &exchange()), Verdict::Ignored);
    }

    #[test]
    fn ignores_a_body_that_is_not_a_callback() {
        assert_eq!(verdict("not json", &exchange()), Verdict::Ignored);
    }

    #[test]
    fn refuses_a_reply_bound_to_another_attempt() {
        let posted = body(r#""id_token":"a.b.c","state":"another","nonce":"page-nonce""#);
        assert!(matches!(verdict(&posted, &exchange()), Verdict::Refused(_)));
    }

    #[test]
    fn refuses_an_empty_token() {
        let posted = body(r#""id_token":"","state":"state-value","nonce":"page-nonce""#);
        assert!(matches!(verdict(&posted, &exchange()), Verdict::Refused(_)));
        let absent = body(r#""state":"state-value","nonce":"page-nonce""#);
        assert!(matches!(verdict(&absent, &exchange()), Verdict::Refused(_)));
    }

    #[test]
    fn reports_a_cancelled_sign_in_as_one() {
        let posted = body(r#""error":"access_denied","state":"state-value","nonce":"page-nonce""#);
        assert_eq!(
            verdict(&posted, &exchange()),
            Verdict::Refused("sign-in was cancelled".to_string())
        );
    }

    #[test]
    fn builds_an_authorize_url_on_the_provider_host() {
        let url = authorize_url("a-client", 14200, &exchange()).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("accounts.google.com"));

        let query: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        assert!(query.contains(&("client_id".into(), "a-client".into())));
        assert!(query.contains(&("response_type".into(), "id_token".into())));
        assert!(query.contains(&("state".into(), "state-value".into())));
        assert!(query.contains(&(
            "redirect_uri".into(),
            "http://127.0.0.1:14200/callback".into()
        )));
    }

    /// RFC 8252 §8.3: a host name would also resolve to `::1`, which another
    /// process can hold and address selection prefers.
    #[test]
    fn the_redirect_names_a_literal_address_and_no_host_name() {
        let uri = redirect_uri(14200);
        assert_eq!(uri, "http://127.0.0.1:14200/callback");
        let parsed = Url::parse(&uri).unwrap();
        let host = parsed.host_str().unwrap();
        assert!(
            host.parse::<std::net::IpAddr>().is_ok(),
            "redirect_uri must carry an IP literal, got {host}"
        );
    }

    #[test]
    fn a_hostile_client_id_cannot_move_the_authorize_host() {
        let url = authorize_url("x&redirect_uri=https://evil.test/#", 14200, &exchange()).unwrap();
        assert_eq!(url.host_str(), Some("accounts.google.com"));
        let redirects: Vec<String> = url
            .query_pairs()
            .filter(|(name, _)| name == "redirect_uri")
            .map(|(_, value)| value.into_owned())
            .collect();
        assert_eq!(
            redirects,
            vec!["http://127.0.0.1:14200/callback".to_string()]
        );
    }

    #[test]
    fn the_callback_page_carries_this_exchange_nonce() {
        assert!(callback_page("page-nonce").contains("\"page-nonce\""));
    }

    #[test]
    fn splits_a_request_into_its_line_and_body() {
        let request = "POST /token HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
        assert_eq!(split(request), Some(("POST /token HTTP/1.1", "{}")));
        assert_eq!(split("GET /callback HTTP/1.1\r\n"), None);
    }

    #[test]
    fn reads_the_declared_body_length_whatever_the_header_case() {
        assert_eq!(content_length("POST / HTTP/1.1\r\ncontent-length: 12"), 12);
        assert_eq!(content_length("POST / HTTP/1.1\r\nContent-Length:  7 "), 7);
        assert_eq!(content_length("POST / HTTP/1.1\r\nHost: localhost"), 0);
        assert_eq!(content_length("POST / HTTP/1.1\r\nContent-Length: many"), 0);
    }

    #[test]
    fn every_exchange_gets_its_own_secrets() {
        let (first, second) = (Exchange::new().unwrap(), Exchange::new().unwrap());
        assert_ne!(first.state, second.state);
        assert_ne!(first.page_nonce, second.page_nonce);
        assert_ne!(first.oidc_nonce, second.oidc_nonce);
        assert_ne!(first.state, first.page_nonce);
        assert_eq!(first.state.len(), 32);
    }
}
