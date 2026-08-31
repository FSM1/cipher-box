//! The headless entry the mounted e2e suite drives (blueprint/desktop.md
//! "Testing hooks": dev-key mode is the headless harness entry).
//!
//! A `--dev-key-stdin` on the command line starts the session with no webview
//! login and no OS keyring, and publishes a loopback control endpoint the suite
//! asks for status, refresh, and quit over. The whole module sits behind the
//! `e2e-hook` cargo feature, so a shipping build holds none of it.

mod cli;
mod control;
mod credentials;

use std::sync::Arc;

use tauri::{AppHandle, Manager};

use crate::engine::EngineHost;

pub use cli::Headless;
pub use credentials::MemoryCredentialStore;

/// The headless start this command line and this standard input ask for, if
/// they ask for one.
///
/// The key line is taken at startup, before the shell builds anything.
pub fn headless() -> Result<Option<Headless>, String> {
    let Some(options) = cli::options(std::env::args_os().skip(1))? else {
        return Ok(None);
    };
    let dev_key = cli::read_dev_key(std::io::stdin().lock())?;
    Ok(Some(Headless {
        dev_key,
        control_file: options.control_file,
    }))
}

/// Arms the headless entry: bind the control endpoint, publish it, then start
/// the engine on the dev key.
///
/// The control file lands before the start, so the suite has an endpoint to
/// watch the cold start through.
pub fn arm(app: &AppHandle, headless: Headless) -> Result<(), String> {
    let Headless {
        dev_key,
        control_file,
    } = headless;
    let token = control::mint_token()?;

    let listener = tauri::async_runtime::block_on(control::bind())?;
    let port = listener
        .local_addr()
        .map_err(|error| format!("the control endpoint has no address: {error}"))?
        .port();
    control::publish(&control_file, port, &token)?;

    let endpoint = Arc::new(control::Control::over(app, token));
    tauri::async_runtime::spawn(control::serve(listener, endpoint));

    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // The secret is the engine's from here: `start` takes it by value and
        // it is zeroized where it dies, exactly as the IPC path leaves it.
        let started = match crate::session::session_env(&app) {
            Ok(env) => app.state::<EngineHost>().start(dev_key, env).await,
            Err(refusal) => Err(refusal),
        };
        if let Err(refusal) = started {
            eprintln!("the headless start failed: {refusal}");
        }
    });
    Ok(())
}
