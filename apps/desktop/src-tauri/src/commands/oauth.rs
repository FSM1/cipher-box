//! OAuth popup window and callback server commands.

use std::sync::atomic::{AtomicU32, Ordering};
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
/// If none of the preferred ports are available, falls back to a random port.
/// A random port requires `http://localhost` (without port) to be registered
/// in Google Cloud Console, which Google allows for Desktop-type OAuth clients.
const PREFERRED_PORTS: &[u16] = &[14200, 14201, 14202];

/// Start a temporary localhost HTTP server to receive OAuth callbacks.
///
/// Google OAuth rejects non-HTTP(S) redirect URIs like `tauri://localhost`.
/// In production Tauri builds, `window.location.origin` resolves to
/// `tauri://localhost` (macOS) or `https://tauri.localhost` (Windows),
/// which Google won't accept.
///
/// This command spins up a short-lived HTTP server on `127.0.0.1`,
/// trying preferred ports first (so the redirect URI can be pre-registered
/// in Google Cloud Console). The server:
///   1. Serves a callback HTML page at any GET request that extracts
///      the OAuth fragment (`#id_token=...`) and POSTs it back
///   2. Receives the POST at `/token`, emits a Tauri event, and shuts down
///
/// Returns the port number so the frontend can build the redirect_uri:
///   `http://localhost:{port}/callback`
///
/// The server auto-terminates after 120 seconds if no callback arrives.
#[tauri::command]
pub async fn start_oauth_server(app: tauri::AppHandle) -> Result<u16, String> {
    // Try preferred ports first (pre-registered in Google Cloud Console)
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

    // Fallback: random port
    let listener = match listener {
        Some(l) => l,
        None => {
            log::warn!(
                "All preferred ports {:?} unavailable, using random port",
                PREFERRED_PORTS
            );
            TcpListener::bind("127.0.0.1:0")
                .await
                .map_err(|e| format!("Failed to bind OAuth callback server: {}", e))?
        }
    };

    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed to get server address: {}", e))?
        .port();

    log::info!("OAuth callback server started on port {}", port);

    // Spawn the server task — it will shut down after receiving the callback
    // or after the timeout (120s).
    tokio::spawn(run_oauth_server(listener, app));

    Ok(port)
}

/// Minimal callback HTML page served by the OAuth callback server.
///
/// This page runs in the OAuth popup webview after Google redirects back.
/// It extracts the token from the URL fragment (implicit flow uses fragments)
/// and POSTs it back to the same localhost server, which then emits a Tauri event.
const CALLBACK_HTML: &str = r#"<!doctype html>
<html>
<head>
<style>body{background:#000;color:#006644;font-family:'JetBrains Mono',monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style>
</head>
<body>
<p id="msg">Completing sign-in...</p>
<script>
(function() {
  var hash = window.location.hash.substring(1);
  var params = new URLSearchParams(hash);
  var idToken = params.get('id_token');
  var error = params.get('error');
  var state = params.get('state');

  // POST the extracted fragment data back to the same server
  fetch('/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      id_token: idToken || null,
      error: error || null,
      state: state || null
    })
  })
  .then(function() {
    document.getElementById('msg').textContent = 'Sign-in complete. You can close this window.';
  })
  .catch(function(err) {
    document.getElementById('msg').textContent = 'Error: ' + err.message;
  });
})();
</script>
</body>
</html>"#;

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

/// OAuth callback data emitted via Tauri event.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
struct OAuthCallbackPayload {
    id_token: Option<String>,
    error: Option<String>,
    state: Option<String>,
}

/// Run the OAuth callback server until a token is received or timeout.
async fn run_oauth_server(listener: TcpListener, app: tauri::AppHandle) {
    let timeout = tokio::time::Duration::from_secs(120);

    loop {
        let accept_result = tokio::select! {
            result = listener.accept() => result,
            _ = tokio::time::sleep(timeout) => {
                log::warn!("OAuth callback server timed out after 120s");
                // Emit error event so the frontend doesn't hang
                let _ = app.emit("oauth-callback", OAuthCallbackPayload {
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
        // Initial read
        match stream.read(&mut buf).await {
            Ok(n) if n > 0 => total = n,
            _ => continue,
        };

        let initial_request = String::from_utf8_lossy(&buf[..total]);

        // Parse the first line to determine method and path
        let first_line = initial_request.lines().next().unwrap_or("");

        if first_line.starts_with("POST /token") {
            // Parse Content-Length from headers to know how much body to expect
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

            // Find where headers end (\r\n\r\n) and calculate how much body we have
            let header_end = initial_request.find("\r\n\r\n").map(|i| i + 4);
            if let Some(header_len) = header_end {
                let body_so_far = total.saturating_sub(header_len);
                let remaining = content_length.saturating_sub(body_so_far);
                // Read remaining body bytes if we don't have everything yet
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

            // Re-parse with full data
            let full_request = String::from_utf8_lossy(&buf[..total]);
            let body = full_request
                .split("\r\n\r\n")
                .nth(1)
                .unwrap_or("");

            let payload: OAuthCallbackPayload =
                serde_json::from_str(body).unwrap_or(OAuthCallbackPayload {
                    id_token: None,
                    error: Some("Failed to parse callback data".to_string()),
                    state: None,
                });

            let has_token = payload.id_token.is_some();
            log::info!(
                "OAuth callback received: has_token={}, error={:?}",
                has_token,
                payload.error
            );

            // Emit the Tauri event to the main webview
            if let Err(e) = app.emit("oauth-callback", payload) {
                log::error!("Failed to emit oauth-callback event: {}", e);
            }

            // Send response and close
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 Access-Control-Allow-Origin: *\r\n\
                 \r\n\
                 {}",
                DONE_HTML.len(),
                DONE_HTML
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;

            // Also close any remaining oauth-popup windows
            close_oauth_popups(&app);

            log::info!("OAuth callback server shutting down");
            return;
        } else if first_line.starts_with("OPTIONS") {
            // Handle CORS preflight for the POST
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
            // Any other GET request (the callback page)
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/html\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {}",
                CALLBACK_HTML.len(),
                CALLBACK_HTML
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        }
    }
}

/// Close all oauth-popup windows.
fn close_oauth_popups(app: &tauri::AppHandle) {
    // Popup labels are "oauth-popup-0", "oauth-popup-1", etc.
    // Try to close a reasonable range.
    for i in 0..100 {
        let label = format!("oauth-popup-{}", i);
        if let Some(window) = app.get_webview_window(&label) {
            let _ = window.close();
        }
    }
}
