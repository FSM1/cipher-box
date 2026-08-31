//! The headless build's loopback control endpoint.
//!
//! One request per connection: `<token> <verb>\n` in, one JSON line out, then
//! the connection closes. The token is 32 bytes of OS entropy minted at bind
//! time and published in the control file, so only a caller that can read that
//! file drives this shell.

use std::io::Write as _;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Manager};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::engine::EngineHost;

/// Bytes of entropy in the control token.
const TOKEN_BYTES: usize = 32;

/// How long one connection may take to deliver its request, so a stalled peer
/// spends its own deadline rather than the endpoint's.
const REQUEST_DEADLINE: Duration = Duration::from_secs(10);

/// A control request is one short line. Anything larger is refused rather than
/// buffered.
const MAX_REQUEST_BYTES: usize = 512;

/// How much of an over-long request is still drained. A connection closed over
/// unread bytes resets, and the refusal would go with the reset.
const MAX_DRAIN_BYTES: usize = 4 * MAX_REQUEST_BYTES;

/// The one refusal a malformed line, an over-long request, and a wrong token
/// all get. A caller may not learn which of the three it sent.
const REFUSED: &str = "the control request was refused";

const NO_SUCH_VERB: &str = "the control endpoint serves no such verb";

/// What one control request asks of the shell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verb {
    /// The live vault's status.
    Status,
    /// The manual refresh with nocache semantics.
    Refresh,
    /// Exit through the normal Tauri path.
    Quit,
}

/// One verb's answer body: the `status` object, or nothing.
type Answered = Result<Option<serde_json::Value>, String>;

type Answering = Pin<Box<dyn Future<Output = Answered> + Send>>;

/// The endpoint's token and what it may ask of the shell.
pub struct Control {
    token: String,
    status: Box<dyn Fn() -> Answering + Send + Sync>,
    refresh: Box<dyn Fn() -> Answering + Send + Sync>,
    quit: Box<dyn Fn() + Send + Sync>,
}

impl Control {
    /// The endpoint over a running shell.
    pub fn over(app: &AppHandle, token: String) -> Self {
        let reading = app.clone();
        let refreshing = app.clone();
        let quitting = app.clone();
        Self {
            token,
            status: Box::new(move || {
                let app = reading.clone();
                Box::pin(async move {
                    let status = app.state::<EngineHost>().status().await?;
                    serde_json::to_value(status)
                        .map(Some)
                        .map_err(|error| error.to_string())
                })
            }),
            refresh: Box::new(move || {
                let app = refreshing.clone();
                Box::pin(async move { app.state::<EngineHost>().refresh().await.map(|()| None) })
            }),
            // The normal exit path: `RunEvent::Exit` ends the session, so the
            // mount is quiesced and unmounted before the process goes.
            quit: Box::new(move || quitting.exit(0)),
        }
    }
}

/// Binds the endpoint on loopback, on a port the OS picks.
pub async fn bind() -> Result<TcpListener, String> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|error| format!("the control endpoint would not bind: {error}"))
}

/// The endpoint's token: 32 bytes of OS entropy as lowercase hex.
pub fn mint_token() -> Result<String, String> {
    let mut bytes = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut bytes).map_err(|_| "this device has no entropy source".to_owned())?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

/// Publishes the endpoint: a temp file beside `path`, then a rename, so a
/// reader sees either nothing or the whole line.
pub fn publish(path: &Path, port: u16, token: &str) -> Result<(), String> {
    let line = control_line(port, token)?;
    let temp = temp_path(path);
    write_owner_only(&temp, line.as_bytes())?;
    std::fs::rename(&temp, path).map_err(|error| {
        format!(
            "the control file would not land at {}: {error}",
            path.display()
        )
    })
}

/// The one line the control file holds: `<port> <token>\n`.
///
/// The request decoder splits on the first space and matches the whole token,
/// so a published token that carried a space or a newline could never be
/// offered back. The check returns `Err` rather than asserting, because a
/// release build strips an assertion and would then publish an endpoint nobody
/// can drive.
fn control_line(port: u16, token: &str) -> Result<String, String> {
    if port == 0 {
        return Err("the control endpoint has no port".to_owned());
    }
    if !minted_shape(token) {
        return Err(format!(
            "the control token is not {} lowercase hex characters",
            TOKEN_BYTES * 2
        ));
    }
    Ok(format!("{port} {token}\n"))
}

/// Whether `token` has the shape [`mint_token`] produces.
fn minted_shape(token: &str) -> bool {
    token.len() == TOKEN_BYTES * 2
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    PathBuf::from(temp)
}

/// Writes `bytes` owner-readable only, where the platform says so, and syncs
/// before the caller renames the file into place.
fn write_owner_only(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        format!(
            "the control file would not open at {}: {error}",
            path.display()
        )
    })?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("the control file would not write: {error}"))
}

/// Serves control requests until the listener stops accepting.
///
/// Each connection is handled on its own task, so a peer that opens and then
/// says nothing spends its own deadline rather than the endpoint's.
pub async fn serve(listener: TcpListener, control: Arc<Control>) {
    while let Ok((stream, _)) = listener.accept().await {
        tokio::spawn(answer(stream, control.clone()));
    }
}

/// Answers one connection.
async fn answer(mut stream: TcpStream, control: Arc<Control>) {
    let read = tokio::time::timeout(REQUEST_DEADLINE, read_request(&mut stream)).await;
    let asked = match read {
        Ok(Some(line)) => request(&line, &control.token),
        _ => Err(REFUSED.to_owned()),
    };
    let verb = match asked {
        Ok(verb) => verb,
        Err(refusal) => {
            respond(&mut stream, &refused(&refusal)).await;
            return;
        }
    };
    let answered = match verb {
        Verb::Status => (control.status)().await,
        Verb::Refresh => (control.refresh)().await,
        Verb::Quit => Ok(None),
    };
    respond(&mut stream, &response(answered)).await;
    if verb == Verb::Quit {
        // The answer is on the wire and the write side is closed before the
        // app goes.
        drop(stream);
        (control.quit)();
    }
}

/// Reads one request line against the endpoint's token.
fn request(line: &str, token: &str) -> Result<Verb, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    let Some((offered, verb)) = line.split_once(' ') else {
        return Err(REFUSED.to_owned());
    };
    if !same_token(offered.as_bytes(), token.as_bytes()) {
        return Err(REFUSED.to_owned());
    }
    match verb {
        "status" => Ok(Verb::Status),
        "refresh" => Ok(Verb::Refresh),
        "quit" => Ok(Verb::Quit),
        _ => Err(NO_SUCH_VERB.to_owned()),
    }
}

/// Compares two tokens in a time that does not depend on where they differ.
fn same_token(offered: &[u8], minted: &[u8]) -> bool {
    offered.len() == minted.len()
        && offered
            .iter()
            .zip(minted)
            .fold(0u8, |differs, (one, other)| differs | (one ^ other))
            == 0
}

/// Reads one newline-terminated request, up to the byte ceiling.
async fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut raw: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 128];
    let mut total = 0usize;
    loop {
        let read = stream.read(&mut chunk).await.ok()?;
        if read == 0 {
            break;
        }
        total += read;
        if total <= MAX_REQUEST_BYTES {
            raw.extend_from_slice(&chunk[..read]);
        }
        if chunk[..read].contains(&b'\n') || total > MAX_DRAIN_BYTES {
            break;
        }
    }
    if total > MAX_REQUEST_BYTES {
        return None;
    }
    String::from_utf8(raw).ok()
}

/// One answer as the line the endpoint writes.
fn response(answered: Answered) -> String {
    match answered {
        Ok(None) => r#"{"ok":true}"#.to_owned(),
        Ok(Some(status)) => format!(r#"{{"ok":true,"status":{status}}}"#),
        Err(error) => refused(&error),
    }
}

/// A refusal line. The message crosses as a JSON string, so nothing it carries
/// can break the one line the caller reads.
fn refused(error: &str) -> String {
    let message = serde_json::Value::String(error.to_owned());
    format!(r#"{{"ok":false,"error":{message}}}"#)
}

async fn respond(stream: &mut TcpStream, line: &str) {
    let _ = stream.write_all(line.as_bytes()).await;
    let _ = stream.write_all(b"\n").await;
    let _ = stream.flush().await;
    let _ = stream.shutdown().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// A made-up token, of the shape [`mint_token`] produces.
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// How many times the endpoint asked its stand-in shell to quit.
    static QUITS: AtomicUsize = AtomicUsize::new(0);

    /// An endpoint over a stand-in shell: `status` answers a fixed object,
    /// `refresh` answers nothing, and `quit` is counted.
    fn control() -> Arc<Control> {
        Arc::new(Control {
            token: TOKEN.to_owned(),
            status: Box::new(|| Box::pin(async { Ok(Some(serde_json::json!({ "items": 7 }))) })),
            refresh: Box::new(|| Box::pin(async { Ok(None) })),
            quit: Box::new(|| {
                QUITS.fetch_add(1, Ordering::Relaxed);
            }),
        })
    }

    async fn listening() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = bind().await.expect("a loopback port");
        let port = listener.local_addr().expect("an address").port();
        (port, tokio::spawn(serve(listener, control())))
    }

    /// Sends one request over a real loopback socket and returns the answer.
    async fn ask(port: u16, sent: &str) -> String {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("the endpoint accepts");
        stream.write_all(sent.as_bytes()).await.expect("sent");
        let mut answer = String::new();
        stream
            .read_to_string(&mut answer)
            .await
            .expect("an answer arrives");
        answer
    }

    #[tokio::test]
    async fn answers_status_on_the_minted_token() {
        let (port, serving) = listening().await;
        let answer = ask(port, &format!("{TOKEN} status\n")).await;
        assert_eq!(answer.trim_end(), r#"{"ok":true,"status":{"items":7}}"#);
        serving.abort();
    }

    #[tokio::test]
    async fn answers_refresh_with_no_body() {
        let (port, serving) = listening().await;
        let answer = ask(port, &format!("{TOKEN} refresh\n")).await;
        assert_eq!(answer.trim_end(), r#"{"ok":true}"#);
        serving.abort();
    }

    #[tokio::test]
    async fn refuses_a_request_that_carries_another_token() {
        let (port, serving) = listening().await;
        let guessed = "f".repeat(TOKEN_BYTES * 2);
        let answer = ask(port, &format!("{guessed} status\n")).await;
        assert_eq!(
            answer.trim_end(),
            format!(r#"{{"ok":false,"error":"{REFUSED}"}}"#)
        );
        serving.abort();
    }

    /// A wrong token may not say which part of the request was wrong, so a
    /// malformed line and a guessed token answer alike.
    #[tokio::test]
    async fn one_refusal_covers_a_wrong_token_and_a_malformed_line() {
        let (port, serving) = listening().await;
        let guessed = ask(port, &format!("{} status\n", "f".repeat(TOKEN_BYTES * 2))).await;
        let malformed = ask(port, "no-space-at-all\n").await;
        let over_long = ask(
            port,
            &format!("{TOKEN} {}\n", "x".repeat(MAX_REQUEST_BYTES)),
        )
        .await;
        assert_eq!(guessed, malformed);
        assert_eq!(guessed, over_long);
        serving.abort();
    }

    #[tokio::test]
    async fn refuses_a_verb_it_does_not_serve() {
        let (port, serving) = listening().await;
        let answer = ask(port, &format!("{TOKEN} unmount\n")).await;
        assert_eq!(
            answer.trim_end(),
            format!(r#"{{"ok":false,"error":"{NO_SUCH_VERB}"}}"#)
        );
        serving.abort();
    }

    #[tokio::test]
    async fn answers_quit_before_it_ends_the_shell() {
        let (port, serving) = listening().await;
        let before = QUITS.load(Ordering::Relaxed);
        let answer = ask(port, &format!("{TOKEN} quit\n")).await;
        assert_eq!(answer.trim_end(), r#"{"ok":true}"#);
        // The answer arrived on a connection the endpoint closed itself, so the
        // quit runs after the write.
        while QUITS.load(Ordering::Relaxed) == before {
            tokio::task::yield_now().await;
        }
        serving.abort();
    }

    #[tokio::test]
    async fn a_stalled_peer_does_not_hold_up_the_next_request() {
        let (port, serving) = listening().await;
        // Opened and never spoken on. Enough of them to outlast the request
        // deadline if each held the endpoint for its own.
        let mut stalled = Vec::new();
        for _ in 0..4 {
            stalled.push(
                TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .expect("the endpoint accepts"),
            );
        }
        let answered =
            tokio::time::timeout(REQUEST_DEADLINE, ask(port, &format!("{TOKEN} status\n")))
                .await
                .expect("the stalled peers starved the endpoint");
        assert!(answered.contains(r#""ok":true"#));
        serving.abort();
    }

    #[test]
    fn reads_each_verb_it_serves() {
        assert_eq!(
            request(&format!("{TOKEN} status\n"), TOKEN),
            Ok(Verb::Status)
        );
        assert_eq!(
            request(&format!("{TOKEN} refresh\r\n"), TOKEN),
            Ok(Verb::Refresh)
        );
        assert_eq!(request(&format!("{TOKEN} quit"), TOKEN), Ok(Verb::Quit));
    }

    #[test]
    fn mints_a_new_token_every_time() {
        let (first, second) = (mint_token().unwrap(), mint_token().unwrap());
        assert_ne!(first, second);
        assert!(minted_shape(&first), "{first} is not the minted shape");
    }

    #[test]
    fn publishes_the_port_and_the_token_on_one_line() {
        assert_eq!(
            control_line(14200, TOKEN).expect("a minted token"),
            format!("14200 {TOKEN}\n")
        );
    }

    /// The encode side holds the invariant the request decoder enforces: a
    /// token with a space, a newline, or a wrong length could never be offered
    /// back, so it is refused here rather than published.
    #[test]
    fn refuses_to_publish_a_token_the_decoder_could_not_match() {
        for refused in [
            "ab cd",
            "abcd\n",
            &TOKEN[..62],
            &TOKEN.to_uppercase(),
            "",
            &format!("{TOKEN}ab"),
        ] {
            assert!(
                control_line(14200, refused).is_err(),
                "{refused:?} was published"
            );
        }
        assert!(control_line(0, TOKEN).is_err(), "port 0 was published");
    }

    #[test]
    fn writes_the_control_file_whole_and_owner_readable() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let path = dir.path().join("control");
        publish(&path, 14200, TOKEN).expect("the control file lands");

        assert_eq!(
            std::fs::read_to_string(&path).expect("the control file reads"),
            format!("14200 {TOKEN}\n")
        );
        assert!(!temp_path(&path).exists(), "the temp file was left behind");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path)
                .expect("the file is there")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0, "the control file is readable by others");
        }
    }
}
