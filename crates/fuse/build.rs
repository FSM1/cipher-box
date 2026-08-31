fn main() {
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("macos") => fuse_t_rpath(),
        Ok("windows") => winfsp_delayload(),
        _ => {}
    }
}

/// FUSE-T's `libfuse-t.dylib` has an `@rpath` install name, and the matching
/// `-Wl,-rpath` its `fuse-t.pc` carries is parsed by the `pkg-config` crate but
/// never forwarded to rustc. A dependency build script's link arg does not
/// reach the final link, so every package that links the adapter states it —
/// which libfuse won is still decided in the vendored `fuser` script.
fn fuse_t_rpath() {
    match pkg_config::Config::new()
        .cargo_metadata(false)
        .probe("fuse-t")
    {
        Ok(lib) => {
            for path in &lib.link_paths {
                println!("cargo:rustc-link-arg=-Wl,-rpath,{}", path.display());
            }
        }
        // Loud, because the binary still links and only fails at load.
        Err(e) => println!("cargo:warning=fuse-t.pc not found, linking no rpath: {e}"),
    }
}

/// WinFsp supports delay-loading only, and the `/DELAYLOAD` link arg that makes
/// it so does not cross a dependency's build script either. This states it for
/// this package's own test binaries; the desktop shell states it again for the
/// app it links.
///
/// Only a Windows host builds a Windows target here: WinFsp's headers and
/// import library come from a local installation, never from a cross toolchain.
#[cfg(windows)]
fn winfsp_delayload() {
    winfsp::build::winfsp_link_delayload();
}

#[cfg(not(windows))]
fn winfsp_delayload() {}
