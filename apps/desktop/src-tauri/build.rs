fn main() {
    // The engine's configuration is compiled in from these variables
    // (`src/engine/config.rs`), so a changed value has to be a rebuild rather
    // than a stale constant. `scripts/tauri.mjs` resolves the first two; the
    // rest reach cargo as this build's own environment.
    for variable in [
        "VITE_API_URL",
        "VITE_ROUTING_ENDPOINTS",
        "VITE_READ_ACCELERATOR_URL",
        "VITE_PUBLIC_GATEWAYS",
        "VITE_ENVIRONMENT",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    link_fuse_t_rpath();
    link_winfsp_delayload();
    tauri_build::build();
}

/// The shell links the macOS host adapter, so its binary needs FUSE-T's search
/// path stated on this package too — see `crates/fuse/build.rs`.
fn link_fuse_t_rpath() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    match pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("fuse-t")
    {
        Ok(lib) => {
            for path in &lib.link_paths {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
            }
        }
        Err(e) => println!("cargo:warning=fuse-t.pc not found, linking no rpath: {e}"),
    }
}

/// The shell links the Windows host adapter, and WinFsp supports delay-loading
/// only, so this binary states the `/DELAYLOAD` arg for the same reason it
/// states the FUSE-T rpath — see `crates/fuse/build.rs`. Without it the shell
/// carries a static import on `winfsp-x64.dll` and will not start on a device
/// that has it installed anywhere but `PATH`.
#[cfg(windows)]
fn link_winfsp_delayload() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winfsp::build::winfsp_link_delayload();
    }
}

#[cfg(not(windows))]
fn link_winfsp_delayload() {}
