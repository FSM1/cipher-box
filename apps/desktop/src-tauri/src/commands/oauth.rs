//! OAuth popup window and callback server commands.

use std::sync::atomic::{AtomicU32, Ordering};
use rand::{thread_rng, Rng};
use tauri::{Emitter, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Counter for unique OAuth popup window labels (shared with tray handler).
static POPUP_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Open an OAuth popup window directly from Rust.
///
/// Bypasses `window.open()` which is unreliable on Windows WebView2 (the
/// `NewWindowRequested` event / `on_new_window` handler may silently fail).
/// Instead, the webview calls this command via `invoke()` to create a new
/// Tauri webview window pointing directly at the OAuth URL.
#[tauri::command]
pub async fn open_oauth_popup(app: tauri::AppHandle, url: String) -> Result<(), String> {
    let n = POPUP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let label = format!("oauth-popup-{}", n);

    let parsed_url: tauri::Url = url
        .parse()
        .map_err(|e| format!("Invalid OAuth URL: {}", e))?;

    // Allowlist: only HTTPS requests to known OAuth providers are permitted.
    const ALLOWED_HOSTS: &[&str] = &["accounts.google.com"];
    if parsed_url.scheme() != "https" {
        return Err("OAuth URL must use HTTPS".to_string());
    }
    let host = parsed_url.host_str().unwrap_or("");
    if !ALLOWED_HOSTS.contains(&host) {
        return Err(format!("OAuth URL host '{}' is not allowed", host));
    }

    log::info!("Creating OAuth popup window: {} -> {}", label, host);

    tauri::WebviewWindowBuilder::new(
        &app,
        &label,
        tauri::WebviewUrl::External(parsed_url),
    )
    .title("Sign in with Google")
    .inner_size(500.0, 700.0)
    .center()
    .build()
    .map_err(|e| format!("Failed to create OAuth popup: {}", e))?;

    Ok(())
}

/// Preferred ports for the OAuth callback server, tried in order.
///
/// These must be registered as authorized redirect URIs in Google Cloud Console:
///   - `http://localhost:14200/callback`
///   - `http://localhost:14201/callback`
///   - `http://localhost:14202/callback`
///
/// If none are available, the server fails fast with a clear error rather than
/// falling back to a random port (which wouldn't be registered in Google Console).
const PREFERRED_PORTS: &[u16] = &[14200, 14201, 14202];

/// Response from `start_oauth_server` — port and scoped event name.
#[derive(Clone, serde::Serialize)]
pub struct OAuthServerInfo {
    port: u16,
    event_name: String,
}

/// Start a temporary localhost HTTP server to receive OAuth callbacks.
///
/// Google OAuth rejects non-HTTP(S) redirect URIs like `tauri://localhost`.
/// In production Tauri builds, `window.location.origin` resolves to
/// `tauri://localhost` (macOS) or `https://tauri.localhost` (Windows),
/// which Google won't accept.
///
/// This command spins up a short-lived HTTP server on `127.0.0.1`,
/// trying preferred ports in order (pre-registered in Google Cloud Console).
/// Fails fast if none are available. The server:
///   1. Serves a callback HTML page (with embedded nonce) that extracts
///      the OAuth fragment (`#id_token=...`) and POSTs it back
///   2. Receives the POST at `/token`, validates the nonce, emits a
///      port-scoped Tauri event, and shuts down
///
/// Returns `{ port, event_name }` so the frontend can build the redirect_uri
/// (`http://localhost:{port}/callback`) and listen for the correct event.
///
/// The server auto-terminates after 120 seconds (absolute deadline).
#[tauri::command]
pub async fn start_oauth_server(app: tauri::AppHandle) -> Result<OAuthServerInfo, String> {
    // Try preferred ports (pre-registered in Google Cloud Console)
    let mut listener = None;
    for &port in PREFERRED_PORTS {
        match TcpListener::bind(format!("127.0.0.1:{}", port)).await {
            Ok(l) => {
                log::info!("OAuth callback server bound to preferred port {}", port);
                listener = Some(l);
                break;
            }
            Err(e) => {
                log::debug!("Preferred port {} unavailable: {}", port, e);
            }
        }
    }

    let listener = listener.ok_or_else(|| {
        format!(
            "All OAuth callback ports {:?} are in use. Close any other CipherBox instances and try again.",
            PREFERRED_PORTS
        )
    })?;

    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get server address: {}", e))?
        .port();

    // Generate a random nonce to validate POSTs (prevents blind injection by local processes)
    let nonce: String = format!("{:016x}", thread_rng().gen::<u64>());
    let event_name = format!("oauth-callback-{}", port);

    log::info!("OAuth callback server started on port {} (event: {})", port, event_name);

    // Spawn the server task — it will shut down after receiving the callback
    // or after the absolute deadline (120s from now).
    tokio::spawn(run_oauth_server(listener, app, event_name.clone(), nonce));

    Ok(OAuthServerInfo { port, event_name })
}

/// Build callback HTML with an embedded nonce for POST validation.
///
/// This page runs in the OAuth popup webview after Google redirects back.
/// It extracts the token from the URL fragment (implicit flow uses fragments)
/// and POSTs it back to the same localhost server with the nonce. The server
/// validates the nonce before emitting the Tauri event.
fn build_callback_html(nonce: &str) -> String {
    format!(
        r#"<!doctype html>
<html>
<head>
<style>body{{background:#000;color:#006644;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}</style>
</head>
<body>
<p id="msg">Completing sign-in...</p>
<script>
(function() {{
  var hash = window.location.hash.substring(1);
  var params = new URLSearchParams(hash);
  var idToken = params.get('id_token');
  var error = params.get('error');
  var state = params.get('state');

  fetch('/token', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json' }},
    body: JSON.stringify({{
      id_token: idToken || null,
      error: error || null,
      state: state || null,
      nonce: '{nonce}'
    }})
  }})
  .then(function() {{
    document.getElementById('msg').textContent = 'Sign-in complete. You can close this window.';
  }})
  .catch(function(err) {{
    document.getElementById('msg').textContent = 'Error: ' + err.message;
  }});
}})();
</script>
</body>
</html>"#,
        nonce = nonce
    )
}

/// Response page shown after the token POST is received.
const DONE_HTML: &str = r#"<!doctype html>
<html>
<head>
<style>body{background:#000;color:#006644;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style>
</head>
<body>
<p>Sign-in complete. You can close this window.</p>
</body>
</html>"#;

/// Incoming POST data from the callback page (includes nonce for validation).
#[derive(serde::Deserialize)]
struct OAuthPostData {
    id_token: Option<String>,
    error: Option<String>,
    state: Option<String>,
    nonce: Option<String>,
}

/// OAuth callback data emitted via Tauri event (nonce stripped).
#[derive(Clone, serde::Serialize)]
struct OAuthCallbackPayload {
    id_token: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

/// Run the OAuth callback server until a token is received or absolute deadline.
async fn run_oauth_server(
    listener: TcpListener,
    app: tauri::AppHandle,
    event_name: String,
    expected_nonce: String,
) {
    // Absolute deadline — connections cannot extend the server lifetime (fix: review #3)
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(120);
    let callback_html = build_callback_html(&expected_nonce);

    loop {
        let accept_result = tokio::select! {
            result = listener.accept() => result,
            _ = tokio::time::sleep_until(deadline) => {
                log::warn!("OAuth callback server timed out (absolute deadline)");
                let _ = app.emit(&event_name, OAuthCallbackPayload {
                    id_token: None,
                    error: Some("OAuth callback server timed out".to_string()),
                    state: None,
                });
                return;
            }
        };

        let (mut stream, _addr) = match accept_result {
            Ok(conn) => conn,
            Err(e) => {
                log::error!("OAuth server accept error: {}", e);
                continue;
            }
        };

        // Read the HTTP request — headers may arrive before the body,
        // so we may need multiple reads for POST requests.
        let mut buf = vec![0u8; 65536];
        let mut total = 0usize;
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => total = n,
            _ => continue,
        };

        let initial_request = String::from_utf8_lossy(&buf[..total]);
        let first_line = initial_request.lines().next().unwrap_or("");

        if first_line.starts_with("POST /token") {
            // Parse Content-Length to know how much body to expect
            let content_length = initial_request
                .lines()
                .find_map(|line| {
                    let lower = line.to_ascii_lowercase();
                    if lower.starts_with("content-length:") {
                        lower.trim_start_matches("content-length:").trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            // Read remaining body bytes if headers arrived before body
            let header_end = initial_request.find("\r\n\r\n").map(|i| i + 4);
            if let Some(header_len) = header_end {
                let body_so_far = total.saturating_sub(header_len);
                let remaining = content_length.saturating_sub(body_so_far);
                if remaining > 0 && total + remaining <= buf.len() {
                    let mut left = remaining;
                    while left > 0 {
                        match stream.read(&mut buf[total..]).await {
                            Ok(0) => break,
                            Ok(n) => { total += n; left = left.saturating_sub(n); }
                            Err(_) => break,
                        }
                    }
                }
            }

            let full_request = String::from_utf8_lossy(&buf[..total]);
            let body = full_request
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("");

            let post_data: OAuthPostData = match serde_json::from_str(body) {
                Ok(d) => d,
                Err(e) => {
                    log::warn!("OAuth POST: invalid JSON body: {}", e);
                    send_response(&mut stream, "400 Bad Request", "Invalid request").await;
                    continue;
                }
            };

            // Validate nonce — reject POSTs not from the callback page we served
            if post_data.nonce.as_deref() != Some(&expected_nonce) {
                log::warn!("OAuth POST: nonce mismatch, ignoring");
                send_response(&mut stream, "403 Forbidden", "Invalid nonce").await;
                continue;
            }

            let payload = OAuthCallbackPayload {
                id_token: post_data.id_token,
                error: post_data.error,
                state: post_data.state,
            };

            let has_token = payload.id_token.is_some();
            log::info!(
                "OAuth callback received: has_token={}, error={:?}",
                has_token,
                payload.error
            );

            // Emit the port-scoped Tauri event to the main webview
            if let Err(e) = app.emit(&event_name, payload) {
                log::error!("Failed to emit {} event: {}", event_name, e);
            }

            send_response(&mut stream, "200 OK", DONE_HTML).await;
            close_oauth_popups(&app);

            log::info!("OAuth callback server shutting down");
            return;
        } else if first_line.starts_with("OPTIONS") {
            let response = "HTTP/1.1 200 OK\r\n\
                            Access-Control-Allow-Origin: *\r\n\
                            Access-Control-Allow-Methods: POST\r\n\
                            Access-Control-Allow-Headers: Content-Type\r\n\
                            Content-Length: 0\r\n\
                            Connection: close\r\n\
                            \r\n";
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        } else {
            // GET request — serve the callback page with embedded nonce
            send_response(&mut stream, "200 OK", &callback_html).await;
        }
    }
}

/// Send a minimal HTTP response with HTML body.
async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: &str,
    body: &str,
) {
    let response = format!(
        "HTTP/1.1 {}\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         Access-Control-Allow-Origin: *\r\n\
         \r\n\
         {}",
        status,
        body.len(),
        body,
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.flush().await;
}

/// Close all oauth-popup windows up to the current counter value.
fn close_oauth_popups(app: &tauri::AppHandle) {
    let current = POPUP_COUNTER.load(Ordering::Relaxed);
    for i in 0..current {
        let label = format!("oauth-popup-{}", i);
        if let Some(window) = app.get_webview_window(&label) {
            let _ = window.close();
        }
    }
}
