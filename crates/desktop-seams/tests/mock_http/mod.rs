//! A tiny loopback HTTP/1.1 server for the transport/HTTP seam tests.
//!
//! Std-only (no extra deps): it speaks just enough HTTP to exercise the
//! `reqwest` seams. Routes:
//!
//! - `PUT|GET /routing/v1/ipns/<key>` — an in-memory `/routing/v1` record
//!   store (PUT stores the body, GET returns it or 404), matching the shape
//!   the [`RecordTransport`] kit drives.
//! - `POST /echo` — echoes the request body and adds an `x-echo: yes`
//!   header; records the request for assertions.
//! - `GET /teapot` — returns 418, to prove a non-2xx status is a response,
//!   not a seam error.
//!
//! Every response carries `Connection: close`, so each request is one
//! connection and the accept loop stays single-threaded.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// One request the server received, captured for test assertions.
#[derive(Clone)]
pub struct RecordedRequest {
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A running loopback mock server. Dropping it stops the accept thread.
pub struct MockServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    last: Arc<Mutex<Option<RecordedRequest>>>,
    handle: Option<JoinHandle<()>>,
}

impl MockServer {
    /// Binds an ephemeral loopback port and starts serving.
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");

        let stop = Arc::new(AtomicBool::new(false));
        let last = Arc::new(Mutex::new(None));
        let store: Arc<Mutex<HashMap<String, Vec<u8>>>> = Arc::new(Mutex::new(HashMap::new()));

        let thread_stop = Arc::clone(&stop);
        let thread_last = Arc::clone(&last);
        let handle = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let _ = handle_conn(stream, &store, &thread_last);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            stop,
            last,
            handle: Some(handle),
        }
    }

    /// The `http://127.0.0.1:<port>` base URL of this server.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The most recent request the server received, if any.
    pub fn last_request(&self) -> Option<RecordedRequest> {
        self.last.lock().expect("lock").clone()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_conn(
    mut stream: TcpStream,
    store: &Mutex<HashMap<String, Vec<u8>>>,
    last: &Mutex<Option<RecordedRequest>>,
) -> std::io::Result<()> {
    // Accepted streams can inherit the listener's non-blocking mode; force
    // blocking reads with a safety timeout.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;

    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > 16 * 1024 * 1024 {
            return Ok(());
        }
    };

    let header_text = String::from_utf8_lossy(&buf[..header_end]).into_owned();
    let mut lines = header_text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().unwrap_or_default().to_owned();
    let path = request_parts.next().unwrap_or_default().to_owned();

    let mut headers = Vec::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_owned();
            let value = value.trim().to_owned();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((name, value));
        }
    }

    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < content_length {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..read]);
    }
    body.truncate(content_length);

    *last.lock().expect("lock") = Some(RecordedRequest {
        headers,
        body: body.clone(),
    });

    let (status, reason, extra_headers, response_body): (u16, &str, Vec<(&str, &str)>, Vec<u8>) =
        if let Some(_key) = path.strip_prefix("/routing/v1/ipns/") {
            if method == "PUT" {
                store.lock().expect("lock").insert(path.clone(), body);
                (200, "OK", Vec::new(), Vec::new())
            } else {
                match store.lock().expect("lock").get(&path) {
                    Some(bytes) => (
                        200,
                        "OK",
                        vec![("content-type", "application/vnd.ipfs.ipns-record")],
                        bytes.clone(),
                    ),
                    None => (404, "Not Found", Vec::new(), Vec::new()),
                }
            }
        } else if path == "/echo" {
            (200, "OK", vec![("x-echo", "yes")], body)
        } else if path == "/teapot" {
            (418, "I'm a teapot", Vec::new(), b"teapot".to_vec())
        } else {
            (404, "Not Found", Vec::new(), Vec::new())
        };

    write_response(&mut stream, status, reason, &extra_headers, &response_body)
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
